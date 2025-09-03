from accounts.models import TemplateSetting


def get_template_for_certificate(cert_type):
    try:
        setting = TemplateSetting.objects.get(certificate_type=cert_type)
        choice = setting.selected_template
    except TemplateSetting.DoesNotExist:
        choice = "default"

    mapping = {
        "default": "login/internship_completion.html",
        "landscape1": "login/landscape_certificate.html",
        "landscape2": "login/landscape_completion.html",
    }
    return mapping.get(choice, "login/internship_completion.html")
