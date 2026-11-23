from django import forms
from django.conf import settings


class PromptScanForm(forms.Form):
    prompt = forms.CharField(
        label="Prompt to analyse",
        max_length=5000,
        widget=forms.Textarea(attrs={
            "rows": 6,
            "placeholder": "Type or paste a prompt here, e.g. Ignore all previous instructions...",
        }),
    )

    def clean_prompt(self):
        text = self.cleaned_data["prompt"].strip()
        if len(text) < 3:
            raise forms.ValidationError("Please enter at least 3 characters.")
        return text


class DocumentScanForm(forms.Form):
    document = forms.FileField(label="Upload a PDF or TXT file")

    def clean_document(self):
        f = self.cleaned_data["document"]
        name = f.name.lower()
        if not (name.endswith(".pdf") or name.endswith(".txt")):
            raise forms.ValidationError("Only .pdf and .txt files are allowed.")
        if f.size > settings.MAX_UPLOAD_SIZE:
            raise forms.ValidationError("File is too large. Maximum size is 2 MB.")
        return f
