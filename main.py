import datetime

import xmltodict
from flask import render_template, request, url_for
from flask import Flask
from flask_mail import Mail, Message as Mess
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from rauth import OAuth1Session
from werkzeug.utils import redirect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from data import db_session
from data.users import User
from data.preferences import Preference
from data.exchanges import Exchange
from data.messages import Message
from rauth.service import OAuth1Service


app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": 'bookrec.service.notification@gmail.com',
    "MAIL_PASSWORD": 'K125*k125*'
}

app.config.update(mail_settings)
mail = Mail(app)


GOODREADS_KEY = 'wkvvh7PIOIzrEFDXpjcQ'
GOODREADS_SECRET = 'UXRpEtPLubfOrxyqZPrRo44Tu2oMU56lCQeS76M'


goodreads = OAuth1Service(
    consumer_key=GOODREADS_KEY,
    consumer_secret=GOODREADS_SECRET,
    name='goodreads',
    request_token_url='https://www.goodreads.com/oauth/request_token',
    authorize_url='https://www.goodreads.com/oauth/authorize',
    access_token_url='https://www.goodreads.com/oauth/access_token',
    base_url='https://www.goodreads.com/'
)


def create_session(access_token, access_token_secret):
    session = OAuth1Session(GOODREADS_KEY,
                            GOODREADS_SECRET,
                            access_token=access_token,
                            access_token_secret=access_token_secret)
    return session


def create_notification_message(message_content):
    msg = Mess(subject="Notification from BookRec",
               sender=app.config.get("MAIL_USERNAME"),
               recipients=[current_user.email],
               body=message_content)
    return msg


class LoginForm(FlaskForm):
    email = EmailField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Log In')


class RegisterForm(FlaskForm):
    email = EmailField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    password_again = PasswordField(validators=[DataRequired()])
    username = StringField(validators=[DataRequired()])
    submit = SubmitField('Sign Up')


class ChooseBookForm(FlaskForm):
    book_name = StringField(validators=[DataRequired()])
    submit = SubmitField('Select Book')


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        session = db_session.create_session()
        current_user.last_login = datetime.datetime.now()
        session.merge(current_user)
        session.commit()
        session.close()


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if current_user.is_authenticated:
        genres = ['General Fiction', 'Romance', 'Speculative Fiction', 'Suspense', 'Western']
        subgenres = ['Action Adventure', 'Amateur Sleuth', 'Category Romance', 'Contemporary Romance', 'Cozy Mystery',
                     'Dark Fantasy', 'Epic Fantasy', 'Espionage / Spies / CIA', 'Fantasy', 'Fantasy Romance', 'Gothic',
                     'Graphic Novel', 'Hard-Boiled', 'Heroic Fantasy / Sword & Sorcery', 'Historical', 'Historical Mystery',
                     'Historical Romance', 'Horror', 'Law Enforcement', 'Legal Thriller', 'Literary', 'Medical Thriller',
                     'Mystery', 'Paranormal Romance', 'Political Thriller', 'Private Investigator', 'Romantic Suspense',
                     'Science Fiction', 'Science Fiction / Fantasy', 'Space Opera', 'Thriller', 'Traditional British',
                     'Traditional Regency', 'Urban Fantasy']
        themes = ['Abuse', 'Accidental Pregnancy', 'Adoption', 'Adultery', 'Alcoholism', 'Alternative History',
                  'Americana', 'Amnesia', 'Apocalypse', 'Arranged Marriage', 'Arthurian Legend', 'Astrology',
                  'Biographical', 'Blackmail', 'Boarding School', 'Books to Movies/TV', 'Chick Lit', 'Christian',
                  'Clean & Wholesome', 'Comedy / Humor', 'Coming of Age', 'Death / Dying', 'Disabilities', 'Divorce',
                  'Dystopian', 'Erotica', 'Fairy Tales / Folklore', 'Falsely Accused', 'Feminism', 'Forensics',
                  'Gay / Lesbian / LGBT', 'Guardian / Ward', 'Hidden Identity', 'Holidays', 'Illustrations / Pictures',
                  'Infidelity', 'Interracial Romance', 'Jane Austen', 'Jewish', 'Kidnapping', 'Locked Door Mystery',
                  'Magic', 'Manga', 'Marriage of Convenience', 'Mashup', 'May / December', 'Medical', 'Military',
                  'Mistaken Identity', 'Music', 'Mythology', 'Nautical', 'Noir', 'Occult & Supernatural', 'Office Romance',
                  'Opposites Attract', 'Paranormal', 'Police Procedural', 'Political', 'Post-Apocalyptic', "Pregnancy",
                  'Psychological Suspense', "Rags to Riches", 'Reincarnation', 'Revenge', "Robin Hood", 'Romantic Elements',
                  'Saga', 'Schools', 'Scottish Highlands', 'Secret Baby', 'Shakespeare', 'Sherlock Holmes','Small Town',
                  'Sports', 'Steampunk', 'Tear Jerker', 'TechnoThriller', 'Time Travel', 'Ugly Duckling',
                  'Visionary & Metaphysical', 'Wagon Train', "Women's Fiction"]
        session = db_session.create_session()
        last_login = current_user.last_login.isoformat(sep=' ', timespec='seconds')
        if request.method == 'POST':
            if 'Preferences' in request.form:
                existing_preferences = session.query(Preference).filter(Preference.user == current_user)
                if existing_preferences:
                    existing_preferences.delete()
                    session.commit()
                for genre in request.form.getlist('genre'):
                    preference = Preference(category='genre', name=genre)
                    current_user.preferences.append(preference)
                for subgenre in request.form.getlist('subgenre'):
                    preference = Preference(category='subgenre', name=subgenre)
                    current_user.preferences.append(preference)
                for theme in request.form.getlist('theme'):
                    preference = Preference(category='theme', name=theme)
                    current_user.preferences.append(preference)

            elif 'Username' in request.form:
                current_user.username = request.form.get('New Username')

            elif 'exitgr' in request.form:
                current_user.access_token = None
                current_user.access_token_secret = None

            elif 'entergr' in request.form:
                global request_token, request_token_secret
                request_token, request_token_secret = goodreads.get_request_token(header_auth=True)
                authorize_url = goodreads.get_authorize_url(request_token)
                return redirect(authorize_url)
            session.merge(current_user)
            session.commit()
        user_genres = ', '.join([value for value, in
                                 session.query(Preference.name).filter(Preference.user == current_user,
                                                                       Preference.category == 'genre').all()])
        user_subgenres = ', '.join([value for value, in
                                    session.query(Preference.name).filter(Preference.user == current_user,
                                                                          Preference.category == 'subgenre').all()])
        user_themes = ', '.join([value for value, in
                                 session.query(Preference.name).filter(Preference.user == current_user,
                                                                       Preference.category == 'theme').all()])
        session.close()
        if request.method == 'POST':
            if 'Password' in request.form:
                if current_user.check_password(request.form.get('Old Password')):
                    current_user.set_password(request.form.get('New Password'))
                else:
                    return render_template('profile.html', genres=genres, subgenres=subgenres, themes=themes,
                                           username=current_user.username, email=current_user.email, log_time=last_login,
                                           message='Wrong Password', user_genres=user_genres, id=current_user.access_token,
                                           user_subgenres=user_subgenres, user_themes=user_themes)
        return render_template('profile.html', genres=genres, subgenres=subgenres, themes=themes, id=current_user.access_token,
                               username=current_user.username, email=current_user.email, log_time=last_login,
                               user_genres=user_genres, user_subgenres=user_subgenres, user_themes=user_themes)
    else:
        return redirect('/signup')


@app.route('/authorized')
def authorized():
    authorize = request.args.get('authorize')
    if authorize == '1':
        session = db_session.create_session()
        gr_session = goodreads.get_auth_session(request_token, request_token_secret)
        current_user.access_token = gr_session.access_token
        current_user.access_token_secret = gr_session.access_token_secret
        session.merge(current_user)
        session.commit()
        session.close()

    return redirect('/profile')


@app.route('/recommend')
def recommend():
    if current_user.is_authenticated:
        session = db_session.create_session()
        current_exchange = session.query(Exchange).filter(Exchange.from_user == current_user, Exchange.current == True)
        session.close()
        if current_exchange:
            return redirect('/recommend_start')
        else:
            return render_template('base.html')
    else:
        return redirect('/signup')


@app.route('/recommend_start')
def recommend_start():
    session = db_session.create_session()
    in_exchange = session.query(Exchange).filter(Exchange.to_user_id == current_user.id, Exchange.current == True).first()
    out_exchange = session.query(Exchange).filter(Exchange.from_user_id == current_user.id,
                                                  Exchange.current == True).first()
    if in_exchange:
        if out_exchange:
            session.close()
            return redirect(url_for('appointed_book', exchange_id=in_exchange.id))
        else:
            if in_exchange.paired_exchange_id:
                session.close()
                return redirect(url_for('appointed_book', exchange_id=in_exchange.id))
            else:
                session.close()
                return redirect(url_for('opponent', opponent_id=in_exchange.from_user_id))
    else:
        if out_exchange and out_exchange.paired_exchange_id == None:
                session.close()
                return redirect('/waiting')
        else:
            active_users = session.query(User).filter(
                User.last_login >= datetime.datetime.now() - datetime.timedelta(days=14),
                User.id != current_user.id, User.current_exchange_id == None,
                User.access_token != None).all()
            cur_user_pref = session.query(Preference.name).filter(Preference.user == current_user).all()
            potent_oponents = []
            if active_users:
                if current_user.access_token:
                    for user in active_users:
                        user_pref = session.query(Preference.name).filter(Preference.user != user).all()
                        num_of_com_elem = len(set(cur_user_pref).intersection(user_pref))
                        potent_oponents.append((user, num_of_com_elem))
                    oponent = sorted(potent_oponents, key=lambda x: x[1], reverse=True)[0]
                    redirect_url = [
                        url_for('opponent', opponent_id=oponent[0].id) if oponent[1] != 0 else '/recommend_failed'][0]
                    session.close()
                else:
                    session.close()
                    redirect_url = '/enter_gr'
            else:
                session.close()
                redirect_url = '/recommend_failed'
            return render_template('recommend_start.html', redirect_url=redirect_url)


@app.route('/recommend_failed')
def recommend_failed():
    return render_template('recommend_failed.html')


@app.route('/enter_gr')
def enter_gr():
    return render_template('enter_gr.html')


@app.route('/opponent?<opponent_id>', methods=['GET', 'POST'])
def opponent(opponent_id):
    form = ChooseBookForm()
    session = db_session.create_session()
    oponent = session.query(User).filter(User.id == opponent_id).first()
    op_genres = ', '.join([value for value, in session.query(Preference.name).filter(Preference.user == oponent,
                                                                                     Preference.category == 'genre').all()])
    op_subgenres = ', '.join([value for value, in session.query(Preference.name).filter(Preference.user == oponent,
                                                                                        Preference.category == 'subgenre').all()])
    op_themes = ', '.join([value for value, in session.query(Preference.name).filter(Preference.user == oponent,
                                                                                     Preference.category == 'theme').all()])
    user_gr_session = create_session(current_user.access_token, current_user.access_token_secret)
    op_gr_session = create_session(oponent.access_token, oponent.access_token_secret)
    op_gr_id = op_gr_session.get('https://www.goodreads.com/api/auth_user')
    op_gr_id = xmltodict.parse(op_gr_id.content)['GoodreadsResponse']['user']['@id']
    op_books = op_gr_session.get('https://www.goodreads.com/review/list.xml',
                                 params={'v': '2', 'id': op_gr_id, 'shelf': 'read', 'per_page': 200})
    op_books = xmltodict.parse(op_books.content)['GoodreadsResponse']['reviews']
    if op_books['@total'] != '0':
        if op_books['@total'] == '1':
            op_books = [op_books['review']['book']['id']['#text']]
        else:
            op_books = [book['book']['id']['#text'] for book in op_books['review']]
        user_gr_id = user_gr_session.get('https://www.goodreads.com/api/auth_user')
        user_gr_id = xmltodict.parse(user_gr_id.content)['GoodreadsResponse']['user']['@id']
        user_books = user_gr_session.get('https://www.goodreads.com/review/list.xml',
                                         params={'v': '2', 'id': user_gr_id, 'shelf': 'read', 'per_page': 200})
        user_books = xmltodict.parse(user_books.content)['GoodreadsResponse']['reviews']
        if user_books['@total'] != '0':
            if user_books['@total'] == '1':
                user_books = [user_books['review']['book']['id']['#text']]
            else:
                user_books = [book['book']['id']['#text'] for book in
                              user_books['review']]
            both_read = list(set(op_books).intersection(user_books))
            b_read = []
            for id in both_read:
                book = op_gr_session.get('https://www.goodreads.com/book/show.xml', params={'id': id})
                book = xmltodict.parse(book.content)['GoodreadsResponse']['book']
                author = book['authors']['author'][0]['name'] if len(book['authors']['author']) < 8 else book['authors']['author']['name']
                b_read.append((book['image_url'], book['title'] + ' by ' + author))
        else:
            b_read = []
    else:
        b_read = []
    session.close()
    if form.validate_on_submit():
        return redirect(url_for('choose_book', book_name=form.book_name.data, opponent_id=oponent.id))

    return render_template('opponent.html', form=form, opponent_name=oponent.username,
                           log_time=oponent.last_login, user_genres=op_genres, user_subgenres=op_subgenres,
                           user_themes=op_themes, both_read=b_read)


@app.route('/choose_book?<book_name>&<opponent_id>')
def choose_book(book_name, opponent_id):
    gr_session = create_session(current_user.access_token, current_user.access_token_secret)
    books = gr_session.get('https://www.goodreads.com/search/index.xml', params={'q': book_name, 'search[field]': 'title'})
    books = xmltodict.parse(books.content)['GoodreadsResponse']['search']['results']['work']
    if not isinstance(books, list):
        books = [books]
    books = [(book['best_book']['title'] + ' by ' + book['best_book']['author']['name'],
              book['best_book']['small_image_url'], book['best_book']['id']['#text']) for book in books]
    return render_template('choose_book.html', books=books, opponent_id=opponent_id)


@app.route('/submit_book?<book_id>&<opponent_id>', methods=['GET', 'POST'])
def submit_book(book_id, opponent_id):
    gr_session = create_session(current_user.access_token, current_user.access_token_secret)
    book = gr_session.get('https://www.goodreads.com/book/show.xml', params={'id': book_id})
    book = xmltodict.parse(book.content)['GoodreadsResponse']['book']
    author = book['authors']['author'][0]['name'] if len(book['authors']['author']) < 8 else book['authors']['author']['name']
    book = [book['image_url'], book['title'], author, book['description'], book['link']]
    if request.method == 'POST':
        session = db_session.create_session()
        session.expire_on_commit = False
        exchange = Exchange(from_user_id=current_user.id, to_user_id=opponent_id, book_name=book[1],
                            user_description=request.form.get('textarea'), book_id=book_id)
        session.add(exchange)
        session.commit()
        oponent = session.query(User).filter(User.id == opponent_id).first()
        oponent.current_exchange_id = exchange.id
        session.merge(oponent)
        session.commit()
        previous_exchange = session.query(Exchange).filter(Exchange.from_user_id == opponent_id,
                                                              Exchange.current == True).first()
        if previous_exchange:
            exchange.paired_exchange_id = previous_exchange.id
            previous_exchange.paired_exchange_id = exchange.id
            session.merge(exchange)
            session.merge(previous_exchange)
            session.commit()
            session.close()
            return redirect(url_for('appointed_book', exchange_id=previous_exchange.id))
        else:
            session.close()
            return redirect('/waiting')
    return render_template('submit_book.html', book=book)


@app.route('/appointed_book?<exchange_id>', methods=['GET', 'POST'])
def appointed_book(exchange_id):
    session = db_session.create_session()
    gr_session = create_session(current_user.access_token, current_user.access_token_secret)
    exchange = session.query(Exchange).filter(Exchange.id == exchange_id).first()
    book_id, opponent_id, user_description = exchange.book_id, exchange.from_user_id, exchange.user_description
    opponent_name = session.query(User.username).filter(User.id == opponent_id).first()[0]
    book = gr_session.get('https://www.goodreads.com/book/show.xml', params={'id': book_id})
    book = xmltodict.parse(book.content)['GoodreadsResponse']['book']
    author = book['authors']['author'][0]['name'] if len(book['authors']['author']) < 8 else book['authors']['author']['name']
    book = [book['image_url'], book['title'], author, book['description'], book['link']]
    if request.method == 'POST':
        gr_session.post('https://www.goodreads.com/shelf/add_to_shelf.xml', data={'name': 'read', 'book_id': book_id})
        exchange.current = False
        current_user.current_exchange_id = None
        session.merge(exchange)
        session.merge(current_user)
        session.commit()
        session.close()
        return redirect('/recommend_start')
    return render_template('appointed_book.html', book=book, opponent_name=opponent_name,
                           user_description=user_description)


@app.route('/waiting')
def waiting():
    return render_template('waiting.html')


@app.route('/discussions')
def discussions_redirect():
    session = db_session.create_session()
    exchange = session.query(Exchange).filter(Exchange.to_user_id == current_user.id).first()
    if exchange.paired_exchange_id:
        return redirect(url_for('discussions', exchange_id=exchange.id))
    else:
        return redirect('/no_discussions')


@app.route('/discussions?<exchange_id>', methods=['GET', 'POST'])
def discussions(exchange_id):
    if current_user.is_authenticated:
        session = db_session.create_session()
        exchange_list = session.query(Exchange).filter(Exchange.to_user_id == current_user.id).all()
        from_message_list = session.query(Message).filter(Message.exchange_id == exchange_id).all()
        message_list = []
        for message in from_message_list:
            message_list.append((1, message.message, message.time_sent))
        paired_exchange_id = session.query(Exchange.paired_exchange_id).filter(Exchange.id == exchange_id).first()
        to_message_list = session.query(Message).filter(Message.exchange_id == paired_exchange_id[0]).all()
        for message in to_message_list:
            message_list.append((0, message.message, message.time_sent))
        message_list = sorted(message_list, key=lambda x: x[2])
        new_exchange_list = []

        for exchange in exchange_list:
            op_book_name = session.query(Exchange.book_name).filter(Exchange.paired_exchange_id == exchange.id).first()[0]
            op_name = session.query(User.username).filter(User.id == exchange.from_user_id).first()[0]
            new_exchange_list.append((exchange.book_name + ' X ' + op_book_name, op_name, exchange.id))

        if request.method == 'POST':
            session = db_session.create_session()
            exchange = Message(exchange_id=exchange_id, message=request.form.get('write_msg'))
            session.add(exchange)
            session.commit()
            session.close()
            return redirect(url_for('discussions', exchange_id=exchange_id))

        return render_template('discussions.html', exchange_list=new_exchange_list, message_list=message_list)
    else:
        return redirect('/signup')


@app.route('/no_discussions')
def no_discussions():
    return render_template('no_discussions.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/login")


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            session.close()
            return redirect("/profile")
        session.close()
        return render_template('login.html',
                               message="Wrong email or password",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        session.close()
        return redirect('/login')
    return render_template('signup.html', title='Регистрация', form=form)


if __name__ == '__main__':
    db_session.global_init("db/bookrec.sqlite")
    app.run(port=8080, host='127.0.0.1')
