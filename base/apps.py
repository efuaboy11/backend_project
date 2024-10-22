from django.apps import AppConfig

class BaseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'base'
    
    def ready(self):
        import base.signals
        
        # Import your tasks here to avoid circular imports
        from background_task import background
        from .tasks import update_investments

        # Schedule the unified task to run every 10 minutes
        update_investments(repeat=10*60)  # Schedule every 10 minutes
