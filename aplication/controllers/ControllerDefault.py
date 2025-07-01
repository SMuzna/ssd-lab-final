from aplication import aplication, limiter
from flask import render_template, redirect, request, url_for, send_file, flash, get_flashed_messages
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash
from aplication import aplication, db
from aplication.models.models import Info
import os
import logging
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'upload') # constante do endereço para armazenar a imagem




@aplication.route('/') # rota da pagina principal
def home():
    return render_template('inicial.html')
    

@aplication.route('/register', methods=['GET', 'POST']) # rota para cadastrar usuarios
@limiter.limit("10 per minute")  # SECURITY: Rate limiting for registration
def register():
    if request.method == 'POST': 
        name = request.form['name'] 
        email = request.form['email'] 
        image = request.form['image'].encode()
        pwd = request.form['password'] 

        # SECURITY: Log registration attempt
        aplication.logger.info(f'Registration attempt for email: {email} from IP: {request.remote_addr}')

        # Check if user already exists
        existing_user = Info.query.filter_by(email=email).first()
        if existing_user:
            aplication.logger.warning(f'Registration failed - email already exists: {email} from IP: {request.remote_addr}')
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('cadastrar.html')

        info = Info(name, email, image, pwd)
        db.session.add(info) #REGISTRANDO O USUARIO NA SESSAO
        db.session.commit() #SALVANDO  OS DADOS NO BANCO
        
        # SECURITY: Log successful registration
        aplication.logger.info(f'Successful registration for email: {email} from IP: {request.remote_addr}')
        flash('Registration successful! Please login.', 'success')

    return render_template( 'cadastrar.html')



@aplication.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # SECURITY: Rate limiting - max 5 login attempts per minute
def login():
    if request.method == 'POST': 
        email = request.form['email']
        pwd = request.form['password']

        # SECURITY: Log login attempt
        aplication.logger.info(f'Login attempt for email: {email} from IP: {request.remote_addr}')

        info = Info.query.filter_by(email=email).first() 

        if not info or not info.verify_password(pwd): 
            # SECURITY: Log failed login attempt
            aplication.logger.warning(f'Failed login attempt for email: {email} from IP: {request.remote_addr}')
            flash('Invalid email or password. Please try again.', 'error')
            return redirect(url_for('login'))
            
        # SECURITY: Log successful login
        aplication.logger.info(f'Successful login for email: {email} from IP: {request.remote_addr}')
        login_user(info) 
        return redirect(url_for('home')) 

    return render_template('login.html') 




@aplication.route('/logout') # rota para sair do usuario
@login_required  # SECURITY: Require authentication to logout
def logout():
    # SECURITY: Log logout activity
    aplication.logger.info(f'User logout from IP: {request.remote_addr}')
    logout_user() 
    return redirect(url_for('login')) 



@aplication.route('/contas') # rota para mostrar os usuarios cadastrados
def contas():
    contas = Info.query.all()
    return render_template( 'contas.html', contas=contas)



@aplication.route('/deletar/<int:id>') # rota para deletar usuarios
@login_required  # SECURITY: Require authentication to delete users
@limiter.limit("5 per minute")  # SECURITY: Rate limiting for delete operations
def deletar(id):
    # SECURITY: Log delete attempt
    aplication.logger.warning(f'User deletion attempt for ID: {id} from IP: {request.remote_addr}')
    
    usuario = Info.query.get(id)
    if usuario:
        db.session.delete(usuario)
        db.session.commit()
        aplication.logger.info(f'User with ID: {id} successfully deleted from IP: {request.remote_addr}')
    else:
        aplication.logger.warning(f'Attempted to delete non-existent user ID: {id} from IP: {request.remote_addr}')
    
    return redirect(url_for('contas'))


@aplication.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required  # SECURITY: Require authentication to edit users
@limiter.limit("10 per minute")  # SECURITY: Rate limiting for edit operations
def editar(id):
    editar_usuario = Info.query.get(id)
    if request.method == 'POST': 
        # SECURITY: Log edit attempt
        aplication.logger.info(f'User edit attempt for ID: {id} from IP: {request.remote_addr}')
        
        editar_usuario.name = request.form['name'] 
        editar_usuario.email = request.form['email']
        editar_usuario.image = request.form['image'].encode() 
        editar_usuario.password = generate_password_hash(request.form['password'])
        
        db.session.commit() # SALVANDO  OS DADOS NO BANCO
        
        # SECURITY: Log successful edit
        aplication.logger.info(f'User with ID: {id} successfully edited from IP: {request.remote_addr}')
        flash('User updated successfully!', 'success')
        
        return redirect(url_for('contas'))
    return render_template( 'editar.html', editar_usuario=editar_usuario)


# UPLOAD DE IMAGEM NA PASTA

# ROTA DO FORMULARIO
@aplication.route('/save')
def form_imagem():      
    return render_template( 'upload.html')


# ROTA PARA UPLOAD
@aplication.route("/upload", methods=['POST'])
@limiter.limit("20 per minute")  # SECURITY: Rate limiting for file uploads
def upload():
    try:
        # SECURITY: Log file upload attempt
        aplication.logger.info(f'File upload attempt from IP: {request.remote_addr}')
        
        file = request.files['image']
        
        # SECURITY: Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            aplication.logger.warning(f'Invalid file type upload attempt from IP: {request.remote_addr}')
            flash('Invalid file type. Only PNG, JPG, JPEG, and GIF files are allowed.', 'error')
            return render_template('upload.html')
        
        savePath = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(savePath)
        
        aplication.logger.info(f'File successfully uploaded from IP: {request.remote_addr}')
        flash('File uploaded successfully!', 'success')
        return render_template('upload.html')
    except Exception as error:
        aplication.logger.error(f'File upload error from IP: {request.remote_addr} - Error: {error}')
        flash('File upload failed. Please try again.', 'error')
        return render_template('upload.html')

# ROTA PARA PEGAR IMAGEM
@aplication.route('/image/<filename>')
def image(filename):
    file = os.path.join(UPLOAD_FOLDER, filename + ".png")
    return send_file(file, mimetype="image/png")
   
