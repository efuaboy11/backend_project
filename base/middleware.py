from django.http import JsonResponse
from .models import BlacklistedIP

class BlockBlacklistedIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        
        if BlacklistedIP.objects.filter(ip_address=ip).exists():
            return JsonResponse({'error': 'Your IP is blackisted'})
        
        response = self.get_response(request)
        return response
    
    