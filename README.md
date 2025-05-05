#### GITHUB 

```
echo "# drf-cbv2" >> README.md
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/edycoleee/drf-cbv2.git
git push -u origin main
```

## 2. AUTH WITH ROLE BASE

### 1. API SPECS

✅ AUTH APIs

| No | URL                      | Method | Auth | Role | Request Body                                | Response                                          |
|----|--------------------------|--------|------|------|---------------------------------------------|---------------------------------------------------|
| 1  | `/auth/register/`        | POST   | ❌ No | All  | `{ "username": "", "password": "" }`         | 201 Created: `{ "id": 1, "username": "" }`        |
| 2  | `/auth/login/`           | POST   | ❌ No | All  | `{ "username": "", "password": "" }`         | `{ "access": "", "refresh": "" }`                 |
| 3  | `/auth/token/refresh/`   | POST   | ❌ No | All  | `{ "refresh": "" }`                          | `{ "access": "" }`                                |
| 4  | `/auth/logout/`          | POST   | ✅ Yes| All  | (No body)                                    | `{ "message": "Logout successful" }`              |
| 5  | `/auth/update-password/` | POST   | ✅ Yes| All  | `{ "new_password": "" }`                     | `{ "message": "Password updated" }`               |


✅ SISWA APIs

| No  | URL              | Method | Auth    | Role  | Request Body / Params                    | Response                        |
|-----|------------------|--------|---------|-------|-------------------------------------------|----------------------------------|
| 6   | `/siswa/`        | POST   | ✅ Yes  | siswa | `{ "siswaname": "", ... }`                | 201 Created: `{...}`             |
| 7   | `/siswa/`        | GET    | ✅ Yes  | admin | (No body)                                 | 200 OK: `[ {...}, {...} ]`       |
| 8   | `/siswa/<id>/`   | GET    | ✅ Yes  | admin | (Path param `id`)                          | 200 OK: `{...}`                  |
| 9   | `/siswa/<id>/`   | PUT    | ✅ Yes  | admin | `{ "siswaname": "", ... }`                | 200 OK: `{...}`                  |
| 10  | `/siswa/<id>/`   | DELETE | ✅ Yes  | admin | (Path param `id`)                          | 204 No Content                   |
| 11  | `/siswa/<id>/`   | PUT    | ✅ Yes  | siswa | Hanya jika `id` milik user sendiri        | 200 OK: `{...}`                  |
| 12  | `/siswa/<id>/`   | GET    | ✅ Yes  | siswa | Hanya jika `id` milik user sendiri        | 200 OK: `{...}`                  |
| 13  | `/siswa/me/`     | GET    | ✅ Yes  | siswa | (No body)                                 | 200 OK: `{...}`                  |

### 2. VENV

```py
# Buat folder project
mkdir belajar-drf
cd belajar-drf

# Buat virtual environment
python -m venv venv

# Aktifkan venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install Django dan Django REST Framework + drf-spectacular(Swagger) + pytest-django(Testing)
pip install django djangorestframework pytest pytest-django drf-spectacular djangorestframework-simplejwt

# Start Django project
django-admin startproject myproject .

# Buat app bernama "siswa"
python manage.py startapp siswa

```
### 3, SQLITE

```py
python3 manage.py dbshell
```

```sql
-- create tabel
CREATE TABLE tb_siswa (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(150) NOT NULL,
    siswaname VARCHAR(150) NOT NULL,
    address TEXT,
    email VARCHAR(150),
    phone VARCHAR(20),
    sex CHAR(1)
);


-- mengetahui semua tabel yang ada
.tables 

-- melihat struktur tabel
PRAGMA table_info(tbl_customer); 
```
CTRL + D >> keluar dari dbshell

### 4. SETTING

```py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_spectacular',
    'siswa',  # tambahkan app
    'rest_framework_simplejwt', #auth jwt
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'TEST_REQUEST_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),
    'AUTH_HEADER_TYPES': ('Bearer',),
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Belajar DRF API',
    'DESCRIPTION': 'API sederhana untuk belajar DRF CBV',
    'VERSION': '1.0.0',
}
```

```
myproject/
├── auth/
│   ├── __init__.py
│   ├── urls.py
│   ├── views.py
│   ├── serializers.py
│   ├── schemas.py
│   └── tests/
│       └── test_auth.py
│
├── siswa/
│   ├── __init__.py
│   ├── urls.py
│   ├── views.py
│   ├── serializers.py
│   ├── schemas.py
│   ├── services.py
│   └── tests/
│       ├── test_create.py
│       ├── test_update.py
│       ├── test_retrieve.py
│       └── test_role_access.py
│
├── myproject/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── db.sqlite3
├── manage.py
└── requirements.txt

```

### 5. AUTH

#### RESPONSE SEDERHANA

```py
GET /siswa/
Response
{
    "message": "Coba List API Siswa"
}
```
```py
# myproject/urls.py
from django.contrib import admin
from django.urls import path,include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('siswa.urls')),  # include url dari app siswa
]

# siswa/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from siswa.views import SiswaViewSet

router = DefaultRouter()
router.register(r'siswa', SiswaViewSet, basename='siswa')

urlpatterns = [
    path('', include(router.urls)),
]

# siswa/views.py
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response


class SiswaViewSet(viewsets.ViewSet):

    def list(self, request):
        data = {"message" : "Coba List API Siswa"}
        return Response(data)

```

```py
python manage.py runserver
```

#### MEMBUAT AUTH


```py
python manage.py migrate
#buat folder auth
```

```py
# pytest.ini
[pytest]
DJANGO_SETTINGS_MODULE = myproject.settings
python_files = tests.py test_*.py *_tests.py
```

```py
# myproject/urls.py
from django.contrib import admin
from django.urls import path,include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('siswa.urls')),  # include url dari app siswa
    path('auth/', include('auth.urls')),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]

### auth/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from auth.views import RegisterView, LogoutView, UpdatePasswordView, MeView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("update-password/", UpdatePasswordView.as_view(), name="update_password"),
    path("me/", MeView.as_view(), name="me"),
]


### auth/views.py
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from auth.serializers import RegisterSerializer, UpdatePasswordSerializer, UserOutputSerializer
from auth.schemas import register_schema, update_password_schema, logout_schema, me_schema

class RegisterView(APIView):
    @register_schema
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.create_user(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            return Response(UserOutputSerializer(user).data, status=201)
        return Response(serializer.errors, status=400)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @logout_schema
    def post(self, request):
        return Response({"message": "Logout successful"}, status=200)

class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    @update_password_schema
    def post(self, request):
        serializer = UpdatePasswordSerializer(data=request.data)
        if serializer.is_valid():
            request.user.set_password(serializer.validated_data["new_password"])
            request.user.save()
            return Response({"message": "Password updated"}, status=200)
        return Response(serializer.errors, status=400)

class MeView(APIView):
    permission_classes = [IsAuthenticated]

    @me_schema
    def get(self, request):
        data = {
            "id": request.user.id,
            "username": request.user.username,
            "role": "admin" if request.user.is_staff else "siswa"
        }
        return Response(data, status=200)


### auth/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'password')
        extra_kwargs = {'password': {'write_only': True}}

class UpdatePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=6)

class UserOutputSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username')


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


### auth/test_auth.py
import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth.models import User

client = APIClient()

@pytest.mark.django_db
def test_register_user():
    response = client.post(reverse("register"), {"username": "testuser", "password": "testpass"})
    assert response.status_code == 201
    assert response.data["username"] == "testuser"

@pytest.mark.django_db
def test_login_user():
    User.objects.create_user(username="testuser", password="testpass")
    response = client.post(reverse("token_obtain_pair"), {"username": "testuser", "password": "testpass"})
    assert response.status_code == 200
    assert "access" in response.data

@pytest.mark.django_db
def test_update_password():
    user = User.objects.create_user(username="testuser", password="testpass")
    login = client.post(reverse("token_obtain_pair"), {"username": "testuser", "password": "testpass"})
    token = login.data["access"]

    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    response = client.post(reverse("update_password"), {"new_password": "newpass123"})
    assert response.status_code == 200
    assert response.data["message"] == "Password updated"

    # test login again
    client.credentials()
    login2 = client.post(reverse("token_obtain_pair"), {"username": "testuser", "password": "newpass123"})
    assert login2.status_code == 200
    assert "access" in login2.data

@pytest.mark.django_db
def test_logout_user():
    user = User.objects.create_user(username="testuser", password="testpass")
    login = client.post(reverse("token_obtain_pair"), {"username": "testuser", "password": "testpass"})
    token = login.data["access"]

    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    response = client.post(reverse("logout"))
    assert response.status_code == 200
    assert response.data["message"] == "Logout successful"

@pytest.mark.django_db
def test_me_info():
    user = User.objects.create_user(username="siswa1", password="testpass")
    login = client.post(reverse("token_obtain_pair"), {"username": "siswa1", "password": "testpass"})
    token = login.data["access"]

    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    response = client.get(reverse("me"))
    assert response.status_code == 200
    assert response.data["username"] == "siswa1"

```
```py
#test
pytest

#coba dengan swagger
http://127.0.0.1:8000/docs/
```

### 6. UTILS
```py
#myproject/utils/db.py
from django.db import connection

from contextlib import contextmanager

@contextmanager
def get_cursor_dict():
    cursor = connection.cursor()
    try:
        yield DictCursor(cursor)
    finally:
        cursor.close()

class DictCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, *args, **kwargs):
        return self.cursor.execute(*args, **kwargs)

    def fetchall(self):
        columns = [col[0] for col in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    @property
    def rowcount(self):
        return self.cursor.rowcount

#myproject/custome_exception.py
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.exceptions import APIException
from rest_framework import status
from myproject.utils.response_wrapper import success_response

class NotFoundException(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'Not found'
    default_code = 'not_found'

def custom_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is not None:
        response.data = success_response(status='error', data=None, message=str(exc))
    return response

#myproject/response_wrapper.py
def success_response(message=None, data=None, status="success"):
    return {
        "status": status,
        "message": message,
        "data": data if data is not None else {}
    }


```

### 7. SISWA 

```py

# siswa/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from siswa.views import SiswaViewSet

router = DefaultRouter()
router.register(r'siswa', SiswaViewSet, basename='siswa')

urlpatterns = [
    path('', include(router.urls)),
]

# siswa/serializers.py
from rest_framework import serializers

class TbSiswaInputSerializer(serializers.Serializer):
    siswaname = serializers.CharField(max_length=100)
    address = serializers.CharField(max_length=255)
    email = serializers.EmailField()
    phone = serializers.CharField(max_length=15)
    sex = serializers.ChoiceField(choices=[("M", "Male"), ("F", "Female")])

class TbSiswaOutputSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    siswaname = serializers.CharField()
    address = serializers.CharField()
    email = serializers.EmailField()
    phone = serializers.CharField()
    sex = serializers.CharField()

# siswa/schemas.py
from drf_spectacular.utils import extend_schema, OpenApiExample
from siswa.serializers import TbSiswaInputSerializer, TbSiswaOutputSerializer

siswa_create_schema = extend_schema(
    request=TbSiswaInputSerializer,
    responses={201: TbSiswaOutputSerializer},
    description="Create new siswa (only for siswa role)",
    examples=[
        OpenApiExample(
            "Create Siswa Example",
            value={
                "siswaname": "Budi Santoso",
                "address": "Jl. Merdeka 10",
                "email": "budi@example.com",
                "phone": "08123456789",
                "sex": "M"
            },
        )
    ]
)

siswa_list_schema = extend_schema(
    responses={200: TbSiswaOutputSerializer(many=True)},
    description="List siswa (only admin)"
)

siswa_retrieve_schema = extend_schema(
    responses={200: TbSiswaOutputSerializer},
    description="Retrieve siswa by ID (admin or siswa by username)"
)

siswa_me_schema = extend_schema(
    responses={200: TbSiswaOutputSerializer},
    description="Get current siswa info (based on JWT user)"
)

# siswa/services.py
from myproject.utils.db import get_cursor_dict

class SiswaService:
    @staticmethod
    def create_siswa(username, data):
        with get_cursor_dict() as cursor:
            cursor.execute(
                """
                INSERT INTO tb_siswa (username, siswaname, address, email, phone, sex)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                [username, data['siswaname'], data['address'], data['email'], data['phone'], data['sex']]
            )
            new_id = cursor.lastrowid
            cursor.execute("SELECT * FROM tb_siswa WHERE id = %s", [new_id])
            return cursor.fetchone()

    @staticmethod
    def get_all_siswa():
        with get_cursor_dict() as cursor:
            cursor.execute("SELECT * FROM tb_siswa")
            return cursor.fetchall()

    @staticmethod
    def get_siswa_by_id(id):
        with get_cursor_dict() as cursor:
            cursor.execute("SELECT * FROM tb_siswa WHERE id = %s", [id])
            return cursor.fetchone()

    @staticmethod
    def get_siswa_by_username(username):
        with get_cursor_dict() as cursor:
            cursor.execute("SELECT * FROM tb_siswa WHERE username = %s", [username])
            return cursor.fetchone()

    @staticmethod
    def update_siswa_by_username(username, data):
        with get_cursor_dict() as cursor:
            cursor.execute(
                """
                UPDATE tb_siswa SET siswaname=%s, address=%s, email=%s, phone=%s, sex=%s
                WHERE username=%s
                """,
                [data['siswaname'], data['address'], data['email'], data['phone'], data['sex'], username]
            )
            cursor.execute("SELECT * FROM tb_siswa WHERE username = %s", [username])
            return cursor.fetchone()

# siswa/views.py
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from siswa.serializers import TbSiswaInputSerializer, TbSiswaOutputSerializer
from siswa.services import SiswaService
from siswa.schemas import *
from myproject.utils.response_wrapper import success_response
from myproject.custome_exception import NotFoundException

class SiswaViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @siswa_create_schema
    def create(self, request):
        if request.user.role != 'siswa':
            return Response(success_response("Unauthorized", status="error"), status=403)
        serializer = TbSiswaInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        siswa = SiswaService.create_siswa(request.user.username, serializer.validated_data)
        return Response(success_response("Siswa created", TbSiswaOutputSerializer(siswa).data), status=201)

    @siswa_list_schema
    def list(self, request):
        if request.user.role != 'admin':
            return Response(success_response("Unauthorized", status="error"), status=403)
        siswa_list = SiswaService.get_all_siswa()
        return Response(success_response("Siswa list", TbSiswaOutputSerializer(siswa_list, many=True).data))

    @siswa_retrieve_schema
    def retrieve(self, request, pk=None):
        siswa = SiswaService.get_siswa_by_id(pk)
        if not siswa:
            raise NotFoundException("Siswa not found")
        if request.user.role == 'admin' or request.user.username == siswa['username']:
            return Response(success_response("Siswa detail", TbSiswaOutputSerializer(siswa).data))
        return Response(success_response("Unauthorized", status="error"), status=403)

    @siswa_me_schema
    @action(detail=False, methods=["get"], url_path="me", permission_classes=[IsAuthenticated])
    def me(self, request):
        siswa = SiswaService.get_siswa_by_username(request.user.username)
        if not siswa:
            raise NotFoundException("Siswa not found")
        return Response(success_response("Current siswa info", TbSiswaOutputSerializer(siswa).data))

```

```py
import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth.models import User
from siswa.services import TbSiswaService

client = APIClient()

@pytest.fixture
def create_user_with_role():
    def _create_user(username, password, role):
        user = User.objects.create_user(username=username, password=password)
        user.profile.role = role
        user.profile.save()
        return user
    return _create_user

@pytest.mark.django_db
def test_siswa_create_as_siswa(create_user_with_role):
    user = create_user_with_role("siswauser", "pass123", "siswa")
    client.force_authenticate(user=user)

    payload = {
        "siswaname": "Budi",
        "address": "Jakarta",
        "email": "budi@mail.com",
        "phone": "08123456789",
        "sex": "M"
    }
    url = reverse("siswa-list")
    response = client.post(url, payload)

    assert response.status_code == 201
    assert response.data["data"]["siswaname"] == "Budi"

@pytest.mark.django_db
def test_siswa_list_as_admin(create_user_with_role):
    admin = create_user_with_role("adminuser", "adminpass", "admin")
    client.force_authenticate(user=admin)

    url = reverse("siswa-list")
    response = client.get(url)

    assert response.status_code == 200
    assert isinstance(response.data["data"], list)

@pytest.mark.django_db
def test_siswa_retrieve_as_siswa(create_user_with_role):
    user = create_user_with_role("siswauser", "pass123", "siswa")
    client.force_authenticate(user=user)

    TbSiswaService.create(
        username=user.username,
        siswaname="Budi",
        address="Jakarta",
        email="budi@mail.com",
        phone="08123456789",
        sex="M",
    )

    url = reverse("siswa-me")
    response = client.get(url)

    assert response.status_code == 200
    assert response.data["data"]["username"] == "siswauser"

@pytest.mark.django_db
def test_siswa_update_as_siswa(create_user_with_role):
    user = create_user_with_role("siswauser", "pass123", "siswa")
    client.force_authenticate(user=user)

    siswa_id = TbSiswaService.create(
        username=user.username,
        siswaname="Budi",
        address="Jakarta",
        email="budi@mail.com",
        phone="08123456789",
        sex="M",
    )

    payload = {
        "siswaname": "Budi Update",
        "address": "Bandung",
        "email": "budiupdate@mail.com",
        "phone": "08999999999",
        "sex": "M"
    }
    url = reverse("siswa-detail", args=[siswa_id])
    response = client.put(url, payload)

    assert response.status_code == 200
    assert response.data["data"]["siswaname"] == "Budi Update"

@pytest.mark.django_db
def test_siswa_delete_as_admin(create_user_with_role):
    admin = create_user_with_role("adminuser", "adminpass", "admin")
    client.force_authenticate(user=admin)

    siswa_id = TbSiswaService.create(
        username="someuser",
        siswaname="Susi",
        address="Bandung",
        email="susi@mail.com",
        phone="0822222222",
        sex="F"
    )

    url = reverse("siswa-detail", args=[siswa_id])
    response = client.delete(url)

    assert response.status_code == 204


```

```py
""from django.db import connection
import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth.models import User

# === Fixtures ===
@pytest.fixture(scope="session", autouse=True)
def create_test_table(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tb_siswa (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    siswaname TEXT NOT NULL,
                    address TEXT,
                    email TEXT,
                    phone TEXT,
                    sex TEXT
                )
            """)

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def setup_users():
    admin = User.objects.create_user(username='admin', password='adminpass', is_staff=True)
    siswa = User.objects.create_user(username='siswa', password='siswapass')
    return {'admin': admin, 'siswa': siswa}

@pytest.fixture
def auth_token(api_client, setup_users):
    def _login(username, password):
        response = api_client.post(reverse('token_obtain_pair'), {'username': username, 'password': password})
        return response.data['access']
    return _login

@pytest.fixture
def setup_siswa_data():
    with connection.cursor() as cursor:
        cursor.execute("""
            INSERT INTO tb_siswa (username, siswaname, address, email, phone, sex)
            VALUES ('siswa', 'Siswa One', 'Jl. A', 'siswa@example.com', '12345', 'M')
        """)
        cursor.execute("""
            INSERT INTO tb_siswa (username, siswaname, address, email, phone, sex)
            VALUES ('other', 'Other User', 'Jl. B', 'other@example.com', '67890', 'F')
        """)
    yield
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM tb_siswa")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='tb_siswa'")  # reset autoincrement

# === Update Test ===
@pytest.mark.django_db
def test_update_siswa_by_admin(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('admin', 'adminpass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    payload = {"siswaname": "Updated Admin", "address": "New Address"}
    response = api_client.put("/siswa/1/", payload, format='json')
    assert response.status_code == 200
    assert response.data["data"]["siswaname"] == "Updated Admin"

@pytest.mark.django_db
def test_update_siswa_by_siswa_own(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    payload = {"siswaname": "Siswa Updated", "address": "New Siswa Addr"}
    response = api_client.put("/siswa/1/", payload, format='json')
    assert response.status_code == 200
    assert response.data["data"]["siswaname"] == "Siswa Updated"

@pytest.mark.django_db
def test_update_siswa_by_siswa_other(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    payload = {"siswaname": "Hack Attempt"}
    response = api_client.put("/siswa/2/", payload, format='json')
    assert response.status_code == 403

# === Delete Test ===
@pytest.mark.django_db
def test_delete_siswa_by_admin(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('admin', 'adminpass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.delete("/siswa/1/")
    assert response.status_code == 200
    assert response.data["message"] == "Deleted"

@pytest.mark.django_db
def test_delete_siswa_by_siswa(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.delete("/siswa/1/")
    assert response.status_code == 403

# === Retrieve Test ===
@pytest.mark.django_db
def test_retrieve_siswa_by_admin(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('admin', 'adminpass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/1/")
    assert response.status_code == 200
    assert response.data["data"]["username"] == "siswa"

@pytest.mark.django_db
def test_retrieve_siswa_by_siswa_own(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/1/")
    assert response.status_code == 200
    assert response.data["data"]["username"] == "siswa"

@pytest.mark.django_db
def test_retrieve_siswa_by_siswa_other(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/2/")
    assert response.status_code == 403

# === List Test ===
@pytest.mark.django_db
def test_list_siswa_by_admin(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('admin', 'adminpass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/")
    assert response.status_code == 200
    assert len(response.data["data"]) >= 2

@pytest.mark.django_db
def test_list_siswa_by_siswa(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/")
    assert response.status_code == 403

```

```py
# === Me Endpoint Test ===
@pytest.mark.django_db
def test_me_endpoint_by_siswa(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('siswa', 'siswapass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/me/")
    assert response.status_code == 200
    assert response.data["data"]["username"] == "siswa"

@pytest.mark.django_db
def test_me_endpoint_by_admin(api_client, auth_token, setup_users, setup_siswa_data):
    token = auth_token('admin', 'adminpass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    response = api_client.get("/siswa/me/")
    assert response.status_code == 404  # Karena admin tidak punya entri di tb_siswa
    assert response.data["status"] == "error"

# === Input Validation Test ===
@pytest.mark.django_db
def test_create_siswa_invalid_input(api_client, auth_token, setup_users):
    token = auth_token('admin', 'adminpass')
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    payload = {
        "siswaname": "",  # Required tapi kosong
        "address": "Test Addr",
        "email": "not-an-email",  # Format salah
        "phone": "abc123",  # Validasi format bebas, jika ingin regex bisa ditambah
        "sex": "X"  # Tidak valid (harus M/F jika validasi diterapkan)
    }
    response = api_client.post("/siswa/", payload, format="json")
    assert response.status_code == 400 or response.status_code == 422
    assert response.data["status"] == "error"

```

### 8. DOCKER COMPOSE

```
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── myproject/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   ├── asgi.py
│   ├── utils/
│   │   └── db.py
│   └── custom_exception.py
├── auth/
│   ├── views.py
│   ├── urls.py
│   ├── serializers.py
│   ├── schemas.py
├── siswa/
│   ├── views.py
│   ├── urls.py
│   ├── serializers.py
│   ├── schemas.py
│   ├── services.py
├── manage.py

```
```dockerfile
# Gunakan base image resmi Python
FROM python:3.10-slim

# Set workdir
WORKDIR /app

# Install dependensi sistem
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirement dan install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy semua source code
COPY . .

# Jalankan migration dan server
CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8000"]

```
```yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - .:/app
    environment:
      - DJANGO_SETTINGS_MODULE=myproject.settings
    command: >
      sh -c "
      python manage.py migrate &&
      python manage.py collectstatic --noinput &&
      gunicorn myproject.wsgi:application --bind 0.0.0.0:8000
      "

```
requirements.txt

```txt
Django>=4.2
djangorestframework
djangorestframework-simplejwt
drf-spectacular
gunicorn
```
settings.py tambahan
```py
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Siswa API',
    'DESCRIPTION': 'API untuk mengelola data siswa dan auth',
    'VERSION': '1.0.0',
}

```
urls.py utama (myproject/urls.py)
```py
from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("auth.urls")),
    path("siswa/", include("siswa.urls")),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema")),
]

```
```
docker-compose build
docker-compose up

Akses di browser:

Swagger Docs: http://localhost:8000/docs
JWT Token: http://localhost:8000/auth/login/
CRUD Siswa: http://localhost:8000/siswa/
```

### 9. SISWA TANPA UTILS

```py
# siswa/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from siswa.views import SiswaViewSet

router = DefaultRouter()
router.register(r'siswa', SiswaViewSet, basename='siswa')

urlpatterns = [
    path('', include(router.urls)),
]

# siswa/views.py
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from siswa.services import SiswaService
from siswa.serializers import TbSiswaInputSerializer, TbSiswaOutputSerializer
from siswa.schemas import (
    siswa_list_schema, siswa_create_schema, siswa_update_schema,
    siswa_retrieve_schema, siswa_delete_schema, siswa_me_schema
)
from auth.permissions import IsAdmin, IsSiswa

class SiswaViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @siswa_list_schema
    def list(self, request):
        if not request.user.is_staff:
            return Response({"detail": "Not allowed."}, status=403)
        data = SiswaService.get_all()
        return Response(data)

    @siswa_create_schema
    def create(self, request):
        if not request.user.groups.filter(name='siswa').exists():
            return Response({"detail": "Only siswa can create."}, status=403)
        serializer = TbSiswaInputSerializer(data=request.data)
        if serializer.is_valid():
            data = SiswaService.create(serializer.validated_data)
            return Response(data, status=201)
        return Response(serializer.errors, status=400)

    @siswa_retrieve_schema
    def retrieve(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"detail": "Not allowed."}, status=403)
        data = SiswaService.get_by_id(pk)
        if not data:
            return Response({"detail": "Not found"}, status=404)
        return Response(data)

    @siswa_update_schema
    def update(self, request, pk=None):
        is_admin = request.user.is_staff
        is_siswa = request.user.groups.filter(name='siswa').exists()
        username = request.user.username

        if not (is_admin or (is_siswa and username == request.data.get('username'))):
            return Response({"detail": "Forbidden."}, status=403)

        serializer = TbSiswaInputSerializer(data=request.data)
        if serializer.is_valid():
            data = SiswaService.update(pk, serializer.validated_data)
            return Response(data)
        return Response(serializer.errors, status=400)

    @siswa_delete_schema
    def destroy(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"detail": "Not allowed."}, status=403)
        SiswaService.delete(pk)
        return Response({"detail": "Deleted"})

    @action(detail=False, methods=["get"], url_path="me", permission_classes=[IsAuthenticated])
    @siswa_me_schema
    def me(self, request):
        username = request.user.username
        data = SiswaService.get_by_username(username)
        if not data:
            return Response({"detail": "Not found"}, status=404)
        return Response(data)

# siswa/serializers.py
from rest_framework import serializers

class TbSiswaInputSerializer(serializers.Serializer):
    username = serializers.CharField()
    siswaname = serializers.CharField()
    address = serializers.CharField()
    email = serializers.EmailField()
    phone = serializers.CharField()
    sex = serializers.ChoiceField(choices=["M", "F"])

class TbSiswaOutputSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    siswaname = serializers.CharField()
    address = serializers.CharField()
    email = serializers.EmailField()
    phone = serializers.CharField()
    sex = serializers.ChoiceField(choices=["M", "F"])

# siswa/schemas.py
from drf_spectacular.utils import extend_schema, OpenApiExample
from siswa.serializers import TbSiswaInputSerializer, TbSiswaOutputSerializer

siswa_create_schema = extend_schema(
    request=TbSiswaInputSerializer,
    responses={201: TbSiswaOutputSerializer},
    examples=[
        OpenApiExample(
            "Example Input",
            value={"username": "siswa1", "siswaname": "Budi", "address": "Jl. Merdeka", "email": "budi@mail.com", "phone": "08123456789", "sex": "M"},
        )
    ]
)

siswa_list_schema = extend_schema(
    responses={200: TbSiswaOutputSerializer(many=True)}
)

siswa_retrieve_schema = extend_schema(
    responses={200: TbSiswaOutputSerializer}
)

siswa_update_schema = extend_schema(
    request=TbSiswaInputSerializer,
    responses={200: TbSiswaOutputSerializer}
)

siswa_delete_schema = extend_schema(
    responses={204: None}
)

siswa_me_schema = extend_schema(
    responses={200: TbSiswaOutputSerializer},
    description="Get current siswa info (based on JWT user)"
)

# siswa/services.py
from django.db import connection

class SiswaService:
    @staticmethod
    def get_all():
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM tb_siswa")
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    @staticmethod
    def get_by_id(pk):
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM tb_siswa WHERE id = %s", [pk])
            row = cursor.fetchone()
            if row:
                columns = [col[0] for col in cursor.description]
                return dict(zip(columns, row))
            return None

    @staticmethod
    def get_by_username(username):
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM tb_siswa WHERE username = %s", [username])
            row = cursor.fetchone()
            if row:
                columns = [col[0] for col in cursor.description]
                return dict(zip(columns, row))
            return None

    @staticmethod
    def create(data):
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO tb_siswa (username, siswaname, address, email, phone, sex)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, [
                data['username'], data['siswaname'], data['address'],
                data['email'], data['phone'], data['sex']
            ])
            id = cursor.fetchone()[0]
        return SiswaService.get_by_id(id)

    @staticmethod
    def update(pk, data):
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE tb_siswa SET username=%s, siswaname=%s, address=%s, email=%s, phone=%s, sex=%s
                WHERE id = %s
            """, [
                data['username'], data['siswaname'], data['address'],
                data['email'], data['phone'], data['sex'], pk
            ])
        return SiswaService.get_by_id(pk)

    @staticmethod
    def delete(pk):
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM tb_siswa WHERE id = %s", [pk])

```

Apa itu @action?
@action adalah dekorator dari rest_framework.decorators yang digunakan untuk menambahkan endpoint tambahan (custom) ke dalam sebuah ViewSet. Ini sangat berguna ketika kamu ingin membuat API seperti /me/ yang bukan bagian dari standar CRUD (list, retrieve, create, update, destroy).


```py

# siswa/views.py
from drf_spectacular.utils import extend_schema
from siswa.serializers import TbSiswaInputSerializer, TbSiswaOutputSerializer

class SiswaViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=TbSiswaInputSerializer,
        responses={201: TbSiswaOutputSerializer},
        description="Create new siswa (only for role: siswa/admin)",
    )
    def create(self, request):
        # ...implementasi
        pass

    @extend_schema(
        responses={200: TbSiswaOutputSerializer},
        description="Retrieve detail siswa by ID (admin) or by username (siswa)"
    )
    def retrieve(self, request, pk=None):
        # ...implementasi
        pass

    @extend_schema(
        request=TbSiswaInputSerializer,
        responses={200: TbSiswaOutputSerializer},
        description="Update data siswa (only for owner or admin)"
    )
    def update(self, request, pk=None):
        # ...implementasi
        pass

    @extend_schema(
        responses={200: TbSiswaOutputSerializer(many=True)},
        description="List semua siswa (admin only)"
    )
    def list(self, request):
        # ...implementasi
        pass

@action(detail=False, methods=["get"], url_path="me", permission_classes=[IsAuthenticated])
@extend_schema(
    responses={200: TbSiswaOutputSerializer},
    description="Get current siswa info (based on JWT user)",
)
def me(self, request):
    # ...implementasi
    pass

```


