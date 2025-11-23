from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import JWTError
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError
from schemas import (
    UserRegistrationResponseSchema, UserRegistrationRequestSchema, DetailResponseSchema,
    UserActivationRequestSchema, MessageResponseSchema,
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema, UserLoginResponseSchema, TokenRefreshRequestSchema, TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.utils import generate_secure_token


router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "model": DetailResponseSchema,
            "description": "User already exists",
        },
        500: {
            "model": DetailResponseSchema,
            "description": "Error occurred",
        }
    }
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        user_exist = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
        if user_exist:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )
        user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User group not found."
            )
        db_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(db_user)
        await db.flush()

        token = ActivationTokenModel(user_id=db_user.id)
        db.add(token)
        await db.commit()

        return db_user

    except HTTPException:
        raise
    except (IntegrityError, SQLAlchemyError):
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def request_password_reset(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):

    user = await db.scalar(select(UserModel).where(UserModel.email == payload.email, UserModel.is_active == True))

    if user:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        token = PasswordResetTokenModel(
            user_id=user.id,
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def reset_password_complete(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):

    user = await db.scalar(select(UserModel).where(UserModel.email == payload.email, UserModel.is_active == True))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_obj = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    if not token_obj or token_obj.token != payload.token:
        if token_obj:
            await db.delete(token_obj)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_obj.expires_at).replace(tzinfo=timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_obj)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = payload.password
        await db.delete(token_obj)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post(
    path="/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema
)
async def user_login(
        request_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == request_data.email)
    )
    if not user or not user.verify_password(request_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id, "email": user.email}
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id, "email": user.email},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
    )
    try:
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    refresh_token = payload.refresh_token
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required."
        )

    try:
        token_data = jwt_manager.decode_refresh_token(refresh_token)
        user_id = token_data.get("user_id")
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token)
    result = await db.execute(stmt)
    refresh_token_obj = result.scalars().first()
    if not refresh_token_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if user.id != refresh_token_obj.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id, "email": user.email}
    )

    return {"access_token": access_token}
