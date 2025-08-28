# i18n.py
from flask import request, redirect, url_for, g
from flask_babel import Babel, gettext as _, get_locale

def init_i18n(app):
    """启用中/英切换：?lang= → Cookie → 浏览器 → 默认 zh"""
    app.config.setdefault('BABEL_DEFAULT_LOCALE', 'zh')
    app.config.setdefault('BABEL_SUPPORTED_LOCALES', ['zh', 'en'])
    app.config.setdefault('BABEL_TRANSLATION_DIRECTORIES', 'translations')

    def _select_locale():
        url_lang = request.args.get('lang')
        if url_lang in app.config['BABEL_SUPPORTED_LOCALES']:
            g._lang_from_url = url_lang
            return url_lang

        cookie_lang = request.cookies.get('lang')
        if cookie_lang in app.config['BABEL_SUPPORTED_LOCALES']:
            return cookie_lang

        return (
            request.accept_languages.best_match(app.config['BABEL_SUPPORTED_LOCALES'])
            or app.config['BABEL_DEFAULT_LOCALE']
        )

    # 兼容不同版本的 Flask-Babel
    try:
        # >= 3.x / 4.x
        babel = Babel(app, locale_selector=_select_locale)
    except TypeError:
        # 2.x 的写法
        babel = Babel(app)

        @babel.localeselector
        def _legacy_locale():
            return _select_locale()

    @app.after_request
    def _persist_lang_cookie(resp):
        lang = getattr(g, '_lang_from_url', None)
        if lang:
            resp.set_cookie('lang', lang, max_age=30*24*3600)
        return resp

    @app.context_processor
    def _inject_locale():
        try:
            cur = str(get_locale())
        except Exception:
            cur = app.config['BABEL_DEFAULT_LOCALE']
        return dict(current_locale=cur, _=_)

    @app.route('/set_language/<lang>')
    def set_language(lang):
        if lang not in app.config['BABEL_SUPPORTED_LOCALES']:
            lang = app.config['BABEL_DEFAULT_LOCALE']
        resp = redirect(request.referrer or url_for('index'))
        resp.set_cookie('lang', lang, max_age=30*24*3600)
        return resp
