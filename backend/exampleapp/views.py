from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse

from .models import Test

def test_list(request):
    data = {"results": {
        "question": "poll.question",
        "pub_date": "poll.pub_date"
    }}    
    return JsonResponse(data)