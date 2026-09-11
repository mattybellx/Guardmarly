from django.http import JsonResponse
from .models import Invoice


def invoice_detail(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id)
    return JsonResponse({"total": invoice.total})
