from django.shortcuts import render

from django.shortcuts import render
from django.views.generic import CreateView
from django.http import HttpResponseRedirect
from django.contrib.auth.views import login
from django.contrib.auth.views import logout
from django.contrib.auth.decorators import login_required

from django.core.urlresolvers import reverse_lazy, reverse

from users.models import MyUser

"""from .forms import CustomUserCreationForm"""


def home(request):
    return render(request, 'users/home.html')

@login_required
def dashboard(request):
    return render(request, 'users/dashboard.html')


def login_view(request, *args, **kwargs):
    if request.user.is_authenticated():
        return HttpResponseRedirect(reverse('users:dashboard'))

    kwargs['extra_context'] = {'next': reverse('users:dashboard')}
    kwargs['template_name'] = 'users/login.html'
    return login(request, *args, **kwargs)


def logout_view(request, *args, **kwargs):
    kwargs['next_page'] = reverse('index')
    return logout(request, *args, **kwargs)

def register(request):

    if request.method == "GET":
        return render(request,'userRegister/register.html')
    else:
        form = request.POST
        first_name = form.get('first_name')
        last_name =  form.get('last_name')
        password = form.get('password')
        confirPassword = form.get('confirmPassword')
        email = form.get('email')

        if not first_name.isalpha() or not last_name.isalpha():
            return render(request,'userRegister/register.html', {'falha':'Nome deve conter apenas letras'})
        if '@' not in email or '.' not in email or ' ' in email:
            return render(request,'userRegister/register.html', {'falha':'Email invalido! Esse e-mail nao esta em um formato valido'})
        if MyUser.objects.filter(email=email).exists():
            return render(request,'userRegister/register.html', {'falha':'Email invalido! Esse e-mail ja esta cadastrado no nosso banco de dados'})
        if len(password) <6 and password!=confirPassword:
            return render(request,'userRegister/register.html', {'falha':'Senha Invalida, digite uma senha com no minimo 6 letras'})
        if password !=confirPassword:
            return render(request,'userRegister/register.html', {'falha':'Senha invalida! Senhas de cadastros diferentes'})


        try:
            user = MyUser.objects.create_user(first_name=first_name,last_name=last_name,password=password,email=email)
        except:
            return render(request,'userRegister/register.html', {'falha':'Email invalido!'})



        user.save()

        return render(request,'users/home.html')

def list_user(request):

    users = MyUser.objects.all()
    return render(request,'users/list_user.html',{'users':users})

def edit_user(request,user_id):

    user = MyUser.objects.get(id=user_id)
    if request.method == "GET":
        return render(request,'users/edit_user.html',{'user':user})
    else:
        form = request.POST
        first_name = form.get('first_name')
        last_name =  form.get('last_name')
        password = form.get('password')
        confirPassword = form.get('confirmPassword')
        email = form.get('email')

        if not first_name.isalpha() or not last_name.isalpha():
            return render(request,'userRegister/register.html', {'falha':'Nome deve conter apenas letras'})
        if '@' not in email or '.' not in email or ' ' in email:
            return render(request,'userRegister/register.html', {'falha':'Email invalido! Esse e-mail nao esta em um formato valido'})
        if MyUser.objects.filter(email=email).exists():
            return render(request,'userRegister/register.html', {'falha':'Email invalido! Esse e-mail ja esta cadastrado no nosso banco de dados'})
        if len(password) <6 and password!=confirPassword:
            return render(request,'userRegister/register.html', {'falha':'Senha Invalida, digite uma senha com no minimo 6 letras'})
        if password !=confirPassword:
            return render(request,'userRegister/register.html', {'falha':'Senha invalida! Senhas de cadastros diferentes'})



        user.first_name = first_name
        user.last_name  =last_name
        user.set_password(password)
        user.email = email

        user.save()

        return render(request,'users/edit_user.html',{'info':'usuario modificado com sucesso'})
