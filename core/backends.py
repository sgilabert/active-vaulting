from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

class RemoteUserBackend(ModelBackend):
  """
  This backend is to be used in conjunction with the ``RemoteUserMiddleware``
  found in the middleware module of this package, and is used when the server
  is handling authentication outside of Django.

  By default, the ``authenticate`` method creates ``User`` objects for
  usernames that don't already exist in the database.  Subclasses can disable
  this behavior by setting the ``create_unknown_user`` attribute to
  ``False``.
  """

  # Create a User object if not already in the database?
  create_unknown_user = True

  def authenticate(self, remote_user, access_token):
    """
    The username passed as ``remote_user`` is considered trusted.  This
    method simply returns the ``User`` object with the given username,
    creating a new ``User`` object if ``create_unknown_user`` is ``True``.

    Returns None if ``create_unknown_user`` is ``False`` and a ``User``
    object with the given username is not found in the database.
    """
    if not remote_user:
      return
    user = None
    username = self.clean_username(remote_user)

    UserModel = get_user_model()

    # Note that this could be accomplished in one try-except clause, but
    # instead we use get_or_create when creating unknown users since it has
    # built-in safeguards for multiple threads.
    if self.create_unknown_user:
      user, created = UserModel._default_manager.get_or_create(**{
        UserModel.USERNAME_FIELD: username
      })
    #  if created:
    #    user = self.configure_user(user)
    else:
      try:
        user = UserModel._default_manager.get_by_natural_key(username)
      except UserModel.DoesNotExist:
        pass
    user = self.configure_user(user, access_token)
    return user

  def clean_username(self, username):
    """
    Performs any cleaning on the "username" prior to using it to get or
    create the user object.  Returns the cleaned username.

    By default, returns the username unchanged.
    """
    return username

  def configure_user(self, user, access_token):
    user.access_token = access_token
    user.save()
    return user