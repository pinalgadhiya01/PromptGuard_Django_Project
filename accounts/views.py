from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from scanner.models import Scan

from .forms import ProfileForm, RegisterForm, UserUpdateForm
from .models import Profile


def register(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            Profile.objects.create(user=user)
            login(request, user)
            messages.success(request, "Welcome to PromptGuard! Your account has been created.")
            return redirect("dashboard")
    else:
        form = RegisterForm()

    return render(request, "accounts/register.html", {"form": form})


@login_required
def profile(request):
    # old users / admin-created users may not have a profile yet
    profile_obj, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = ProfileForm(request.POST, instance=profile_obj)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, "Your profile has been updated.")
            return redirect("profile")
    else:
        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileForm(instance=profile_obj)

    recent = Scan.objects.filter(user=request.user)[:5]
    return render(request, "accounts/profile.html", {
        "user_form": user_form,
        "profile_form": profile_form,
        "recent": recent,
        "total_scans": Scan.objects.filter(user=request.user).count(),
    })
