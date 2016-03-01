# Create your models here.
from mongoengine import StringField, ReferenceField, ListField, IntField, DateTimeField, BooleanField, \
    EmbeddedDocumentField
from mongoengine import Document, EmbeddedDocument
from django_oauth2_mongoengine.constants import CLIENT_TYPES, SCOPES
from django_oauth2_mongoengine.utils import long_token, short_token, get_token_expiry, serialize_instance, \
    deserialize_instance, get_code_expiry, now
from django.conf import settings
try:
    from django.utils import timezone
except ImportError:
    timezone = None

def import_from_string(val):
    """
    Attempt to import a class from a string representation.
    """
    try:
        from django.utils import importlib
        # Nod to tastypie's use of importlib.
        parts = val.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        raise ImportError(str(e))
UserModel = import_from_string(getattr(settings, 'USER_MODEL', 'Document'))






class Grant(Document):
    """
    Default grant implementation. A grant is a code that can be swapped for an
    access token. Grants have a limited lifetime as defined by
    :attr:`constants.EXPIRE_CODE_DELTA` and outlined in
    :rfc:`4.1.2`

    """
    code = StringField(max_length=255, default=long_token)
    expires = DateTimeField(default=get_code_expiry)
    redirect_uri = StringField(max_length=255, blank=True)
    scope = IntField(default=0)


class RefreshAccessToken(Document):
    """
    Default refresh token implementation. A refresh token can be swapped for a
    new access token when said token expires.
    """
    token = StringField(max_length=255, default=long_token)
    expired = BooleanField(default=False)


class AccessToken(Document):
    """
    Default access token implementation. An access token is a time limited
    token to access a user's resources.

    Access tokens are outlined :rfc:`5`.

    Expected methods:

    * :meth:`get_expire_delta` - returns an integer representing seconds to
        expiry
    """
    token = StringField(max_length=255, default=long_token, db_index=True)
    expires = DateTimeField(default=self.get_expire_delta())
    scope = IntField(default=SCOPES[0][0], choices=SCOPES)
    refresh_access_token = ListField(ReferenceField('RefreshAccessToken'))

    def get_expire_delta(self, reference=None):
        """
        Return the number of seconds until this token expires.
        """
        if reference is None:
            reference = now()
        expiration = self.expires

        if timezone:
            if timezone.is_aware(reference) and timezone.is_naive(expiration):
                # MySQL doesn't support timezone for datetime fields
                # so we assume that the date was stored in the UTC timezone
                expiration = timezone.make_aware(expiration, timezone.utc)
            elif timezone.is_naive(reference) and timezone.is_aware(expiration):
                reference = timezone.make_aware(reference, timezone.utc)

        timedelta = expiration - reference
        return timedelta.days * 86400 + timedelta.seconds






class Client(Document):
    """
    Default client implementation.

    Clients are outlined in the :rfc:`2` and its subsections.
    """
    grant = ListField(ReferenceField('Grant'))
    access_token = ListField(ReferenceField('AccessToken'))
    name = StringField(max_length=255)
    url = StringField()
    redirect_uri = StringField()
    client_id = StringField(max_length=255, default=short_token)
    client_secret = StringField(max_length=255, default=long_token)
    client_type = IntField(choices=CLIENT_TYPES)

    #def save(self, *args, **kwargs):
        #public = (self.client_type == 1)
        #if not self.access_token.expires:
        #    self.access_token.expires = get_token_expiry(public)
    #    super(Client, self).save(*args, **kwargs)

    def serialize(self):
        return dict(user=serialize_instance(self.user),
                    name=self.name,
                    url=self.url,
                    redirect_uri=self.redirect_uri,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    client_type=self.client_type)



    @classmethod
    def deserialize(cls, data):
        if not data:
            return None

        kwargs = {}

        # extract values that we care about
        for field in cls._meta.fields:
            name = field.name
            val = data.get(field.name, None)

            # handle relations
            if val and field.rel:
                val = deserialize_instance(field.rel.to, val)

            kwargs[name] = val

        return cls(**kwargs)




class User(UserModel):
    #TODO Inherit From Settings User
    #client = ListField(EmbeddedDocumentField(Client))
    client = ListField(ReferenceField(Client))
    grant = ListField(ReferenceField('Grant'))
    refresh_token = ListField(ReferenceField('RefreshAccessToken'))
    access_token = ListField(ReferenceField('AccessToken'))







