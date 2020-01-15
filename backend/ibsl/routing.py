from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import exampleapp.routing

application = ProtocolTypeRouter({
    # (http->django views is added by default)
    'websocket':
        URLRouter(
            exampleapp.routing.websocket_urlpatterns
        )

})
