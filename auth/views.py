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