import json

from django.http import JsonResponse


# class Engines(object):
def check_requests(request):
    method = request.method
    data = {}
    if method == "POST":
        data = json.loads(request.body)
        return data
    else:
        return JsonResponse({"message": "Wrong request method"}, status=401)
