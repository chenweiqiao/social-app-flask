from flask import g, Blueprint, request, session
from flask_security import login_required, login_user, current_user

from social_core.actions import do_auth, do_complete, do_disconnect
from social_flask.utils import psa


social_auth = Blueprint('social', __name__)


@social_auth.route('/login/<string:backend>/', methods=('GET', 'POST'))
@psa('social.complete')
def auth(backend):
    return do_auth(g.backend)


@social_auth.route('/complete/<string:backend>/', methods=('GET', 'POST'))
@psa('social.complete')
def complete(backend, *args, **kwargs):
    """Authentication complete view, override this view if transaction
    management doesn't suit your needs."""
    return do_complete(g.backend, login=do_login, user=current_user,
                       *args, **kwargs)


@social_auth.route('/disconnect/<string:backend>/', methods=('POST',))
@social_auth.route('/disconnect/<string:backend>/<int:association_id>/',
                   methods=('POST',))
@social_auth.route('/disconnect/<string:backend>/<string:association_id>/',
                   methods=('POST',))
@login_required
@psa()
def disconnect(backend, association_id=None):
    """Disconnects given backend from current logged in user."""
    return do_disconnect(g.backend, current_user, association_id)


def do_login(backend, user, social_user):
    name = backend.strategy.setting('REMEMBER_SESSION_NAME', 'keep')
    remember = backend.strategy.session_get(name) or \
               request.cookies.get(name) or \
               request.args.get(name) or \
               request.form.get(name) or \
               False
    return login_user(user, remember=remember)
