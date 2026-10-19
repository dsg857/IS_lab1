from django.shortcuts import HttpResponse
from .models import Collection

# CVE-2021-35042: ORDER BY takes an expression, not a bind parameter, so user
# input must never be passed to order_by() directly. Map it onto a fixed
# allowlist instead and reject everything else.
ALLOWED_ORDER_FIELDS = {'id', 'name'}


def vul(request):
    query = request.GET.get('order', default='id')
    descending = query.startswith('-')
    field = query[1:] if descending else query
    if field not in ALLOWED_ORDER_FIELDS:
        return HttpResponse('Invalid order parameter.', status=400)
    q = Collection.objects.order_by(('-' if descending else '') + field)
    return HttpResponse(q.values())
