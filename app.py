import sqlite3
import uuid
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.utils import secure_filename
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT NOT NULL,
                picture_saved TEXT
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 로그인 제한 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                ip TEXT PRIMARY KEY,
                fail_count INTEGER DEFAULT 0,
                last_fail_time TEXT
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
def get_client_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
    return request.remote_addr


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = get_client_ip()
        db = get_db()
        cursor = db.cursor()


        # IP 로그인 시도 횟수 체크
        cursor.execute("SELECT fail_count, last_fail_time FROM login_attempts WHERE ip = ?", (ip,))
        record = cursor.fetchone()

        if record:
            fail_count = record['fail_count']
            last_fail_time = record['last_fail_time']

            # 2. 5회 초과 && 5분 이내면 차단
            if fail_count >= 5 and last_fail_time:
                last_dt = datetime.strptime(last_fail_time, '%Y-%m-%d %H:%M:%S')
                if datetime.now() - last_dt < timedelta(minutes=5):
                    flash(f'로그인이 제한되었습니다. 5분 후 다시 시도해주세요.')
                    return redirect(url_for('login'))
                else:
                    # 제한 시간 지난 경우 초기화
                    cursor.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
                    db.commit()

        # 3. 사용자 확인
        cursor.execute("SELECT id, password FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and user['password'] == password:
            # 로그인 성공 → IP 실패 기록 삭제
            session['user_id'] = user['id']
            cursor.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
            db.commit()
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            # 로그인 실패
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if record:
                cursor.execute("""
                    UPDATE login_attempts 
                    SET fail_count = fail_count + 1, last_fail_time = ?
                    WHERE ip = ?
                """, (now, ip))
            else:
                cursor.execute("""
                    INSERT INTO login_attempts (ip, fail_count, last_fail_time)
                    VALUES (?, 1, ?)
                """, (ip, now))
            db.commit()
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
        
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 업데이트
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        action = request.form.get('action_type')

        # 소개글 업데이트
        if action == 'update_bio':
            bio = request.form.get('bio', '')
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
            db.commit()
            flash('프로필이 업데이트되었습니다.')

        # 비밀번호 변경
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            if not user or user['password'] != current_password:
                flash('현재 비밀번호가 올바르지 않습니다.')
            else:
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_password, session['user_id']))
                db.commit()
                flash('비밀번호가 변경되었습니다.')

        # 계정 삭제
        elif action == 'delete_account':
            cursor.execute("DELETE FROM user WHERE id = ?", (session['user_id'],))
            db.commit()
            session.pop('user_id', None)
            flash('계정이 삭제되었습니다.')
            return redirect(url_for('index'))

        return redirect(url_for('profile'))
    
    # GET 요청 시 사용자 정보 불러오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 파일 확장자 검증 함수
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'products')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title       = request.form['title']
        description = request.form['description']
        price       = request.form['price']
        product_id  = uuid.uuid4().hex

        # 상품 사진 저장
        file = request.files.get('picture')

        if file and allowed_file(file.filename):
              
            # 디렉토리가 없으면 생성
            product_folder = os.path.join(app.config['UPLOAD_FOLDER'], product_id)
            if not os.path.exists(product_folder):
                os.makedirs(product_folder)
            
            # 파일 경로를 upload 폴더 하위 부분만 저장
            saved_path = os.path.join(app.config['UPLOAD_FOLDER'], product_id, secure_filename(file.filename))
            saved_name = os.path.join(product_id, secure_filename(file.filename))
            
            try:
                file.save(saved_path)
            except Exception as e:
                flash(f'파일 저장 중 오류가 발생했습니다: {str(e)}')
                return redirect(url_for('my_products'))
            
        # DB 저장
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
        INSERT INTO product (id, title, description, price, seller_id, status,
                             picture_saved)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (product_id, title, description, price, session['user_id'], 'available',
          saved_name))
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('new_product.html')

# 내 상품 확인
@app.route('/my_products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    products = cursor.fetchall()
    return render_template('my_products.html', products=products)

# 상품 수정
@app.route('/product/update/<product_id>', methods=['POST'])
def update_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form['title']
    description = request.form['description']
    price = request.form['price']

    db = get_db()
    cursor = db.cursor()

    # 소유권 확인
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()
    if not product:
        flash('해당 상품을 수정할 수 없습니다.')
        return redirect(url_for('my_products'))
    
    file = request.files.get('picture')

    if file and allowed_file(file.filename):
        # 기존 파일 삭제
        if product['picture_saved']:
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], product['picture_saved'])
            if os.path.exists(old_file_path):
                try:
                    os.remove(old_file_path)
                except Exception as e:
                    flash(f'기존 파일 삭제 중 오류가 발생했습니다: {str(e)}')

        # 새 파일 저장
        saved_name = secure_filename(file.filename)
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], product_id)

        saved_path = os.path.join(folder_path, saved_name)
        saved_name = os.path.join(product_id, saved_name)

        try:
            file.save(saved_path)
        except Exception as e:
            flash(f'파일 저장 중 오류가 발생했습니다: {str(e)}')
            return redirect(url_for('my_products'))

        # DB 업데이트
        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?, picture_saved = ?
            WHERE id = ? AND seller_id = ?
        """, (title, description, price, saved_name, product_id, session['user_id']))
    else:
        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ? AND seller_id = ?
        """, (title, description, price, product_id, session['user_id']))

    db.commit()
    flash('상품이 수정되었습니다.')
    return redirect(url_for('my_products'))


# 상품 삭제
@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 소유권 확인
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()
    if not product:
        flash('해당 상품을 삭제할 수 없습니다.')
        return redirect(url_for('my_products'))

    # 저장된 이미지 폴더 삭제
    if product['picture_saved']:
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], product_id)
        if os.path.exists(folder_path):
            try:
                shutil.rmtree(folder_path)
            except Exception as e:
                flash(f'이미지 폴더 삭제 중 오류가 발생했습니다: {str(e)}')

    cursor.execute("DELETE FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.세')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone() 
    # 상품 사진 경로 설정
    picture_path = None
    if product['picture_saved']:
        picture_path = product['picture_saved']  # 실제 경로에 맞게 수정
    
    return render_template('view_product.html', product=product, seller=seller, picture_path=picture_path)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 세션 관리
# 애플리케이션 설정 (한번만)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)

@app.before_request
def manage_session_timeout():
    session.permanent = True

    now = datetime.utcnow()
    last_activity = session.get('last_activity')

    if last_activity:
        elapsed = now - datetime.fromisoformat(last_activity)
        if elapsed > app.config['PERMANENT_SESSION_LIFETIME']:
            # 30분 이상 활동이 없었으면 세션 초기화하고 로그인 요구
            session.clear()
            flash('세션이 만료되었습니다. 다시 로그인해 주세요.')
            return redirect(url_for('login'))

    # 매 요청마다 마지막 활동 시각을 업데이트
    session['last_activity'] = now.isoformat()


if __name__ == '__main__':
    with app.app_context():
        init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
