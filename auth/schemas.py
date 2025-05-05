### auth/schemas.py
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse, OpenApiParameter
from auth.serializers import RegisterSerializer, UpdatePasswordSerializer, UserOutputSerializer

register_schema = extend_schema(
    request=RegisterSerializer,
    responses={201: UserOutputSerializer},
    examples=[
        OpenApiExample("Register Example", value={"username": "user1", "password": "123456"})
    ]
)

update_password_schema = extend_schema(
    request=UpdatePasswordSerializer,
    responses={200: OpenApiResponse(description="Password updated")},
    examples=[
        OpenApiExample("Update Password", value={"new_password": "newpass123"})
    ],
    parameters=[
        OpenApiParameter(name='Authorization', type=str, location=OpenApiParameter.HEADER, required=True,
                         description='JWT access token. Format: Bearer <access_token>')
    ]
)

logout_schema = extend_schema(
    responses={200: OpenApiResponse(description="Logout successful")},
    parameters=[
        OpenApiParameter(name='Authorization', type=str, location=OpenApiParameter.HEADER, required=True,
                         description='JWT access token. Format: Bearer <access_token>')
    ]
)

me_schema = extend_schema(
    responses={200: OpenApiExample("User Info", value={"id": 1, "username": "user1", "role": "siswa"})},
    parameters=[
        OpenApiParameter(name='Authorization', type=str, location=OpenApiParameter.HEADER, required=True,
                         description='JWT access token. Format: Bearer <access_token>')
    ]
)