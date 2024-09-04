from flask import Flask, request, render_template, redirect, url_for, session, flash,send_file
import sqlite3
import hashlib
import base64
from flask import Response
import tempfile
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import io
import matplotlib
matplotlib.use('Agg')

app = Flask(__name__)
app.secret_key = 'your_secret_keyzs'






conn = sqlite3.connect("database.db")
conn.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)")
conn.execute("CREATE TABLE IF NOT EXISTS sections(id INTEGER PRIMARY KEY, Title TEXT, Data TEXT, Image BLOB,Description TEXT)")
conn.execute("CREATE TABLE IF NOT EXISTS books(id INTEGER PRIMARY KEY, Title TEXT, Author TEXT,Book BLOB, Image BLOB,Content TEXT,Rate INTEGER,Page INTEGER ,section_id INTEGER,FOREIGN KEY (section_id) REFERENCES sections(id))")
conn.execute("CREATE TABLE IF NOT EXISTS BookRequest (id INTEGER PRIMARY KEY,user_name TEXT NOT NULL, book_title TEXT NOT NULL,status TEXT DEFAULT 'Pending', UNIQUE(user_name, book_title))")
conn.execute("CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,username TEXT NOT NULL,email TEXT NOT NULL,feedback TEXT NOT NULL)")
conn.execute("CREATE TABLE IF NOT EXISTS book_access (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,book_id INTEGER NOT NULL,access_expiration TIMESTAMP NOT NULL,UNIQUE(user_id,book_id))")
conn.execute("CREATE TABLE IF NOT EXISTS bookcopy AS SELECT * FROM books")
conn.execute("CREATE TABLE IF NOT EXISTS completed_books (id INTEGER PRIMARY KEY AUTOINCREMENT,user_name TEXT NOT NULL,title TEXT NOT NULL,author TEXT NOT NULL)")

cursor = conn.cursor()

try:
    cursor.execute("CREATE TABLE IF NOT EXISTS bookcopy AS SELECT * FROM books")
    cursor.execute("PRAGMA foreign_keys=off")
    cursor.execute("DROP INDEX IF EXISTS bookcopy_pkey")
    conn.commit()
except sqlite3.Error as e:
    print("Error:", e)
finally:
    conn.close()






def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()




def authenticate_user(username, password):
    hashed_password = hash_password(password)
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    data = cur.fetchone()
    con.close()
    return data

def is_admin(username):
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT role FROM users WHERE username=?", (username,))
    role = cur.fetchone()
    con.close()
    return role['role'] == 'admin' if role else False

@app.route("/")
def frontpage():
    return render_template('frontpage.html')


@app.route("/admin_new_section")
def admin_new_section():
    return render_template('admin_new_section.html')






#Section...............

#create a Section
@app.route('/sections/create', methods=['GET', 'POST'])
def add_section():
    if request.method == "POST":
        Title = request.form.get('Title')
        Data = request.form.get('Data')
        Image = request.form.get('Image')
        Description = request.form.get('Description')
        if Title is None or Data is None  or Description is None:
            flash("Please provide all required information", "error")
            return redirect(url_for('admin_new_section'))
        
        conn = sqlite3.connect("database.db")
        # conn.execute('PRAGMA foreign_keys = ON')
        conn.execute("INSERT INTO sections(Title, Data, Image,Description) VALUES (?, ?, ?, ?)", (Title, Data, Image,Description))
        conn.commit() 
        conn.close()
        flash("Book added successfully", "success")
        return redirect(url_for('admin_new_section'))
    return render_template('admin_home.html')

#display a Section
@app.route("/sections")    
def show_sections():
    username = "Library Admin"
    conn = sqlite3.connect("database.db")
    # conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM sections")
    sections = cur.fetchall()
    conn.close()
    return render_template('admin_home.html', sections=sections,username=username)


#delete a Section
@app.route('/sections/<int:section_id>/delete', methods=['GET', 'POST'])
def delete_section(section_id):
    conn = sqlite3.connect("database.db")
    # conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

   
    cur.execute("SELECT * FROM sections WHERE id = ?", (section_id,))
    section = cur.fetchone()

    if not section:
        flash('Section not found!', 'error')
        return redirect(url_for('show_sections'))

    if request.method == 'POST':
        
        cur.execute("DELETE FROM sections WHERE id = ?", (section_id,))
        cur.execute("DELETE FROM books WHERE section_id = ?", (section_id,))
        conn.commit()
        conn.close()

        flash('Section deleted successfully!', 'success')
        return redirect(url_for('show_sections'))

    conn.close()
    return render_template('admin_new_section', section=section)

#Update a Section
@app.route('/sections/<int:section_id>/update', methods=['GET', 'POST'])
def update_section(section_id):
    conn = sqlite3.connect("database.db")
    # conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

   
    cur.execute("SELECT * FROM sections WHERE id = ?", (section_id,))
    section = cur.fetchone()

    if not section:
        flash('Section not found!', 'error')
        return redirect(url_for('show_sections'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

  
        cur.execute("UPDATE sections SET Title = ?, Description = ? WHERE id = ?", (name, description, section_id))
        conn.commit()
        conn.close()

        flash('Section updated successfully!', 'success')
        return render_template('update_section.html', section=section)
    

    conn.close()
    return render_template('admin_new_section')


#books.............

def allowed_file(filename):
    return '.' in filename

def upload_image(file):
    if file and allowed_file(file.filename):
        file_data = file.read()
        encoded_image = base64.b64encode(file_data).decode('utf-8')
        return encoded_image
    
#create a book
@app.route('/books/create/<int:section_id>', methods=['GET', 'POST'])
def add_books(section_id):
    # section_id = session.get('section_id')
    if request.method == 'POST':
        title = request.form.get('title')   
        author = request.form.get('author')
        content = request.form.get('content')
        rating = request.form.get('rating')
        page = request.form.get('page')
        # section_id = request.form.get('section_id')
        
        file = request.files.get('image')
        image = upload_image(file)

        file = request.files.get('Book')
        book = upload_image(file)

        if not all([title, author, content, rating]):
            flash('All fields are required!', 'error')
            return render_template('add_book.html',section_id=section_id)

        conn = sqlite3.connect("database.db")
       
        conn.execute("INSERT INTO books(Title, Author,Book,Image, Content,Rate,Page,section_id) VALUES (?, ?, ?, ?, ?,?,?,?)",
                     (title, author, book,image, content,rating,page,section_id))
        conn.commit()
        conn.close()
        
        flash("Book added successfully", "success")
        return redirect(url_for('add_books',section_id=section_id))

    return render_template('add_book.html',section_id=section_id)


#display a book
@app.route('/books/<int:section_id>', methods=['GET', 'POST']) 
def show_books(section_id):
    conn = sqlite3.connect("database.db")
    
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM books")
    books = cur.fetchall()
    conn.close()
    return render_template('admin_books.html', books=books,section_id=section_id)


#delete a book
@app.route('/books/<int:book_id>/delete', methods=['GET', 'POST'])
def delete_book(book_id):
    conn = sqlite3.connect("database.db")
    # conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    
    cur.execute("SELECT * FROM books WHERE id = ?", (book_id,))
    book = cur.fetchone()
    section_id = book['section_id']

    if not book:
        flash('book not found!', 'error')
        return redirect(url_for('show_books',section_id=section_id))

    if request.method == 'POST':
        
        cur.execute("DELETE FROM books WHERE id = ?", (book_id,))
        conn.commit()
        conn.close()

        flash('E-book deleted successfully!', 'success')
        return redirect(url_for('show_books',section_id=section_id))

    conn.close()
    return render_template('admin_books.html',book=book,section_id=section_id)

#update a book
@app.route('/books/<int:book_id>/update', methods=['GET', 'POST'])
def update_book(book_id):
    conn = sqlite3.connect("database.db")
    # conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()


    cur.execute("SELECT * FROM books WHERE id = ?", (book_id,))
    book = cur.fetchone()
    section_id = book['section_id']

    cur.execute("SELECT * FROM sections")
    section = cur.fetchall()

    if not book:
        flash('E-book not found!', 'error')
        return redirect(url_for('list_ebooks'))

    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        content = request.form.get('content')
        page = request.form.get('Page')
        

    
        cur.execute("UPDATE books SET Title = ?, Author = ?, Content = ?,Page=? WHERE id = ?", 
                    (title, author, content,page,book_id))
        conn.commit()
        conn.close()

        flash('E-book updated successfully!', 'success')
        return render_template('update_book.html', book=book, section_id=section_id)

    conn.close()
    return render_template('admin_new_section', section=section)


#...............................................__

def get_books(query=''):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    
    if query:
        cur.execute("""
            SELECT bc.*,sections.title AS section_name
            FROM bookcopy bc
            INNER JOIN sections ON bc.section_id = sections.id
            WHERE bc.title LIKE ? OR bc.author LIKE ? OR sections.title LIKE ?
        """, ('%' + query + '%', '%' + query + '%', '%' + query + '%'))
    else:
        cur.execute("""
            SELECT bc.*,sections.title AS section_name
            FROM bookcopy bc
            INNER JOIN sections ON bc.section_id = sections.id
        """)

    books = cur.fetchall()
    conn.close()
    return books

def get_books1(query=''):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()


    if query:
        cur.execute("""
            SELECT bc.*,sections.title AS section_name
            FROM books bc
            INNER JOIN sections ON bc.section_id = sections.id
            WHERE bc.title LIKE ? OR bc.author LIKE ? OR sections.title LIKE ?
        """, ('%' + query + '%', '%' + query + '%', '%' + query + '%'))
    else:
        cur.execute("""
            SELECT bc.*,sections.title AS section_name
            FROM books bc
            INNER JOIN sections ON bc.section_id = sections.id
        """)

    books = cur.fetchall()
    conn.close()
    return books

#..........................
#search-admin
@app.route('/search_books')
def search_books():
    query = request.args.get('query', '')
    search_results = get_books1(query)
    return render_template('search.html', search_results=search_results)

#search-user
@app.route('/search_user_books')
def search_user_books():
    query = request.args.get('query', '')
    search_results = get_books(query)
    return render_template('search_user.html', search_results=search_results)



#.........................................

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            conn = sqlite3.connect("database.db")
            cur = conn.cursor()
            hashed_password = hash_password(password)
            cur.execute("INSERT INTO users(username, password, email, role) VALUES (?, ?, ?, ?)", (username, hashed_password, email, "user"))
            cur.execute("INSERT INTO users(username, password, email, role) VALUES (?, ?, ?, ?)", ("ladmin", hash_password("ladmin"),"librarian@gmail.com","ladmin"))
            conn.commit()
            conn.close()
            flash("SignUp Successfully", "success")
        except Exception as e:
            
            flash("Error in signup. Please try again later.", "danger")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route("/login", methods=['GET', "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = authenticate_user(username, password)
        if user_data:
            session["username"] = user_data["username"]
            session["role"] = user_data["role"]
            flash("Login Successful", "success")
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error=True)
    return render_template('login.html', error=False)

@app.route('/home', methods=["GET","POST"])
def home():
    if 'username' in session:
        if session['role'] == 'ladmin':
            return redirect(url_for("show_sections"))
        else:
            return redirect(url_for("User_home"))
    else:
        return redirect(url_for("login"))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))


#---------------------------------------------------------------------
#Admin

@app.route('/adminreq')
def Admin_req():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM BookRequest")
    users= cur.fetchall()
    conn.close()
    return render_template('admin_req.html',users=users)


@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
  
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("UPDATE BookRequest SET status = 'Rejected' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('Admin_req'))  

@app.route('/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("UPDATE BookRequest SET status = 'Accepted' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('Admin_req'))



@app.route('/viewbooks', methods=['GET', 'POST']) 
def view_books():
    conn = sqlite3.connect("database.db")
    
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM sections")
    sections = cur.fetchall()
    cur.execute("SELECT * FROM books")
    books = cur.fetchall()
    conn.close()
    return render_template('view_books.html', books=books,sections=sections)

@app.route('/admindashboard', methods=['GET', 'POST'])
def admin_dashboard():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM bookcopy")
    available_books = cur.fetchall()

    cur.execute("""
        SELECT book_access.user_id, users.username AS user_name, COUNT(*) AS num_books_taken, GROUP_CONCAT(books.title, ', ') AS books_taken
        FROM book_access 
        JOIN users ON book_access.user_id = users.id 
        JOIN books ON book_access.book_id = books.id
        GROUP BY book_access.user_id
    """)
    user_books_taken = cur.fetchall()

    cur.execute("SELECT * FROM feedback")
    feedbacks = cur.fetchall()

    cur.execute("""
    SELECT sections.Title, COUNT(*) AS num_books 
    FROM books 
    JOIN sections ON books.section_id = sections.id 
    GROUP BY sections.Title
    """)
    data = cur.fetchall()

    conn.close()

    sections = [row['Title'] for row in data]
    num_books = [row['num_books'] for row in data]

    plt.bar(sections, num_books)
    plt.xlabel('Section')
    plt.ylabel('Number of Books')
    plt.title('Number of Books Available in Each Section')
    


    img_bytes = io.BytesIO()
    plt.savefig(img_bytes, format='png')
    plt.close()

    img_data = base64.b64encode(img_bytes.getvalue()).decode()

    return render_template('admin_dashboard.html', available_books=available_books, user_books_taken=user_books_taken, feedbacks=feedbacks, graph_data=img_data)


#-------------------------------------------------------------------
#User

@app.route('/Userhome',methods=["POST","GET"])
def User_home():
    if 'username' in session:
        username = session['username']
    conn = sqlite3.connect("database.db")
    
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM sections")
    sections = cur.fetchall()
    cur.execute("SELECT * FROM bookcopy")
    books = cur.fetchall()
    
    conn.close()
    return render_template('user_home.html', books=books,sections=sections,username=username)


@app.route('/Userbooks',methods=["POST","GET"])
def User_books():
    if 'username' in session:
        username = session['username']
        conn = sqlite3.connect("database.db")
        
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT book_title FROM BookRequest WHERE user_name=? and status=?", (username, "Accepted",))
        books_titles = cur.fetchall()

        
        books = []

        for book_title in books_titles:
            cur.execute("SELECT * FROM books WHERE title=?", (book_title['book_title'],))
            book_details = cur.fetchone()
            if book_details:
                books.append(book_details)
                access_book(book_details['id'])
                cur.execute("DELETE FROM bookcopy WHERE Title=?", (book_title['book_title'],))
                conn.commit()  

            

        conn.close()

        return render_template('user_books.html', books=books,username=username)

MAX_BOOKS_PER_USER = 5
@app.route('/Userreq/<title>', methods=["POST", "GET"])
def User_req(title):
    if 'username' in session:
        username = session['username']
        conn = sqlite3.connect("database.db")
        try:
            cur = conn.cursor()
          
            cur.execute("SELECT COUNT(*) FROM BookRequest WHERE user_name = ?", (username,))
            book_count = cur.fetchone()[0]
            if book_count >= MAX_BOOKS_PER_USER:
                flash("You have reached the maximum number of books allowed per user.", "danger")
            else:
                
                cur.execute("INSERT INTO BookRequest(user_name, book_title) VALUES (?, ?)", (username, title))
                conn.commit()
                flash("Book request submitted successfully", "success")
        except sqlite3.Error as e:
            flash("An error occurred while processing your request. Please try again later.", "danger")
        finally:
            conn.close()
    else:
        flash("You must be logged in to request books.", "danger")
    return redirect(url_for('view_req'))



@app.route('/view_book/<int:book_id>')
def view_book(book_id):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT Book FROM books WHERE id = ?", (book_id,))
    book_data = cur.fetchone()[0]
    conn.close()

    pdf_data = base64.b64decode(book_data)

    response = Response(pdf_data, mimetype='application/pdf')
    response.headers['Content-Disposition'] = 'inline; filename=book.pdf'

    return response
    
 

@app.route('/buy_book/<int:book_id>',methods=["POST", "GET"])
def buy_book(book_id):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT Book FROM books WHERE id = ?", (book_id,))
    book_data = cur.fetchone()[0]
    conn.close()

    pdf_data = base64.b64decode(book_data)

    temp_pdf_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    temp_pdf_file.write(pdf_data)
    temp_pdf_file.close()
    pdf= send_file(
        temp_pdf_file.name,
        as_attachment=True)

    return pdf
    

@app.route('/view_book_pdf/<int:book_id>')
def view_book_pdf(book_id):
    return render_template('view_book_copy.html',book_id=book_id)



@app.route('/viewreq',methods=["POST","GET"])
def view_req():
    if 'username' in session:
        username = session['username']
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM BookRequest WHERE user_name=?",(username,))
    users= cur.fetchall()
    conn.close()
    return render_template('view_req.html',users=users)

@app.route('/delreq/<book_title>',methods=["POST","GET"])
def del_req(book_title):
    if request.method == "POST":
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("DELETE FROM BookRequest WHERE book_title=?", (book_title,))
        conn.commit()
        conn.close()
        return redirect(url_for('view_req'))

@app.route('/feedback/<title>', methods=['POST','GET'])
def feed(title):
    return render_template('user_feedback.html',title=title)

@app.route('/book_details/<book_title>',methods=["POST","GET"])
def book_details(book_title):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM books WHERE title = ?", (book_title,))
    book = cur.fetchone()
    conn.close()

    if book:
        return render_template('book_details.html', book=book)
    else:
        return "Book not found", 404
    


@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'username' in session:
        username = session['username']
    name = request.form.get('name')
    email = request.form.get('email')
    feedback = request.form.get('feedback')

    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO feedback (name, username,email, feedback) VALUES (?, ?,?, ?)", (name, username,email, feedback))
    conn.commit()
    conn.close()
    return redirect('/Userhome')

@app.route('/access_book/<int:book_id>')
def access_book(book_id):
    if 'username' in session:
        username = session['username']
  
    try:
            
        access_expiration = datetime.now() + timedelta(days=7)

            
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        user_id = cur.fetchone()[0]
        cur.execute("INSERT INTO book_access (user_id, book_id, access_expiration) VALUES (?, ?, ?)", (user_id, book_id, access_expiration))
        conn.commit()
        conn.close()
    except Exception as e:
        return redirect(url_for('view_book_pdf', book_id=book_id))

    return redirect(url_for('view_book_pdf', book_id=book_id))

@app.route('/return_book/<int:book_id>',methods=['POST','GET'])
def return_book(book_id):
    if 'username' in session:
        username = session['username']
 
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?",(username,))
    user_id=cur.fetchone()[0]
    cur.execute("SELECT * FROM books WHERE id=?", (book_id,))
    book_details = cur.fetchone()

    cur.execute("INSERT INTO completed_books (title, author,user_name) VALUES (?, ?,?)",
                (book_details[1], book_details[2],username,))
        
    cur.execute("INSERT INTO bookcopy (Title, Author, Book, Image, Content, Rate, Page, section_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (book_details[1], book_details[2], book_details[3], book_details[4], book_details[5], book_details[6], book_details[7], book_details[8]))


    cur.execute("DELETE FROM book_access WHERE user_id=? AND book_id=?", (user_id, book_id))

    cur.execute("DELETE FROM BookRequest WHERE user_name=?",(username,))
    
    conn.commit()
    conn.close()

   
    return redirect(url_for('User_home'))

@app.route('/userdashboard', methods=["POST", "GET"])
def dashboard():
    if 'username' in session:
        username = session['username']
     
        conn = sqlite3.connect("database.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

       
        cur.execute("SELECT * FROM completed_books WHERE user_name=?", (username,))
        completed_books = cur.fetchall()

    
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        user_id = cur.fetchone()[0]

     
        cur.execute("SELECT book_id, access_expiration FROM book_access WHERE user_id=?", (user_id,))
        book_access_records = cur.fetchall()

        books = []
       
        for record in book_access_records:
            book_id = record[0]
            access_expiration = record[1]
            cur.execute("SELECT title, author FROM books WHERE id=?", (book_id,))
            book_details = cur.fetchone()
            if book_details:
                book_title = book_details[0]
                book_author = book_details[1]
                books.append({
                    'id': book_id,
                    'title': book_title,
                    'author': book_author,
                    'access_expiration': access_expiration
                })

        conn.commit()
        conn.close()

        return render_template('user_dashboard.html', books=books, completed_books=completed_books)
    
    return render_template('user_dashboard.html', books=books,completed_books=completed_books)




#..................______________________>>>>>>>>>>

if __name__ == '__main__':
    app.run(debug=True)
