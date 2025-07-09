from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .models import EncryptedFile
import os
from django.conf import settings
from .forms import UploadForm
from cryptography.fernet import Fernet
from django.core.files.base import ContentFile
from django.http import HttpResponse, Http404
from .models import EncryptedFile



def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'fileapp/login.html', {'error': 'Invalid username or password'})

    return render(request, 'fileapp/login.html')


def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            return render(request, 'fileapp/register.html', {'error': 'Passwords do not match'})

        if User.objects.filter(username=username).exists():
            return render(request, 'fileapp/register.html', {'error': 'Username already exists'})

        user = User.objects.create_user(username=username, email=email, password=password1)
        user.save()
        return redirect('login')

    return render(request, 'fileapp/register.html')


def logout_view(request):
    logout(request)
    return redirect('login')


FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

@login_required(login_url='login')
def home_view(request):
    message = ''
   
    if request.method == 'POST':
        form = UploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            original_name = uploaded_file.name

            # Encrypt file
            file_data = uploaded_file.read()
            encrypted_data = cipher.encrypt(file_data)

            encrypted_name = f'encrypted_{original_name}'
            encrypted_file = ContentFile(encrypted_data, name=encrypted_name)

            EncryptedFile.objects.create(
                user=request.user,
                original_filename=original_name,
                encrypted_file=encrypted_file
            )

            message = f"{original_name} uploaded and encrypted successfully."
    else:
        form = UploadForm()

    uploaded_files = EncryptedFile.objects.filter(user=request.user)

    return render(request, 'fileapp/home.html', {
    'user': request.user,
    'form': form,
    'message': message,
    'uploaded_files': uploaded_files
})

def decrypt_file(request, file_id):
    try:
        encrypted_obj = EncryptedFile.objects.get(id=file_id, user=request.user)

        # Read encrypted content
        encrypted_data = encrypted_obj.encrypted_file.read()

        # Decrypt the file content using the same cipher
        decrypted_data = cipher.decrypt(encrypted_data)

        # Return as downloadable file or inline preview
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'inline; filename="decrypted_{encrypted_obj.original_filename}"'
        return response

    except EncryptedFile.DoesNotExist:
        raise Http404("File not found.")
    except Exception as e:
        return HttpResponse(f"Error decrypting file: {str(e)}", status=500)