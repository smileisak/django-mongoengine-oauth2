import json

from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.
from django.views.generic import TemplateView
from django.utils.translation import ugettext as _
from django_oauth2_mongoengine.backend import AccessTokenBackend
from django_oauth2_mongoengine.constants import ENFORCE_SECURE
from django_oauth2_mongoengine.helpers import AccessToken
from django_oauth2_mongoengine.models import Client, User
from . import constants
from .utils import now


class OauthDetailsView(TemplateView):

    def post(self, request):
        if ENFORCE_SECURE and not request.is_secure():
            return self.error_response({
                'error': 'invalid_request',
                'error_description': _("A secure connection is required.")})

        if not 'username' in request.POST:
            return self.error_response({
                'error': 'invalid_request',
                'error_description': _("No 'username' included in the "
                    "request.")})
        if not 'client_type' in request.POST:
            return self.error_response({
                'error': 'invalid_request',
                'error_description': _("No 'client_type' included in the "
                    "request.")})
        username = request.POST['username']
        client_type = request.POST['client_type']
        client = Client(name="test_for_smile", client_type=client_type)
        user = User.objects(username=username).first()
        if not user:
            raise Exception #TODO NotFoundException
        user.client.append(client)
        user.save()
        content_type = 'application/json'
        status = 200
        return HttpResponse(json.dumps({"client_id": client.client_id,
                                        "client_secret":client.client_secret,
                                        "group_list": user.group_list,
                                        "id": str(user.id)}), content_type=content_type, status=status)





    def error_response(self, error, content_type='application/json', status=400, **kwargs):
        """
        Return an error response to the client with default status code of
        *400* stating the error as outlined in :rfc:`5.2`.
        """
        return HttpResponse(json.dumps(error), content_type=content_type, status=status, **kwargs)



class AccessTokenView(AccessToken):
    authentication = (
        AccessTokenBackend
    )


    def get_access_token(self, request, user, scope, client):
        try:
            # Attempt to fetch an existing access token.
            at = AccessToken.objects.get(user=user, client=client,
                                         scope=scope, expires__gt=now())
        except AccessToken.DoesNotExist:
            # None found... make a new one!
            at = self.create_access_token(request, user, scope, client)
            self.create_refresh_token(request, user, scope, at, client)
        return at

    def create_access_token(self, request, user, scope, client):
        return AccessToken.objects.create(
            user=user,
            client=client,
            scope=scope
        )

    def create_refresh_token(self, request, user, scope, access_token, client):
        return RefreshToken.objects.create(
            user=user,
            access_token=access_token,
            client=client
        )

    def invalidate_grant(self, grant):
        if constants.DELETE_EXPIRED:
            grant.delete()
        else:
            grant.expires = now() - timedelta(days=1)
            grant.save()

    def invalidate_refresh_token(self, rt):
        if constants.DELETE_EXPIRED:
            rt.delete()
        else:
            rt.expired = True
            rt.save()

    def invalidate_access_token(self, at):
        if constants.DELETE_EXPIRED:
            at.delete()
        else:
            at.expires = now() - timedelta(days=1)
            at.save()