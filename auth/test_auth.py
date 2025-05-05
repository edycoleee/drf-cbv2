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