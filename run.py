from flask import render_template, request, redirect, url_for


from aplication import aplication
from aplication.controllers import ControllerDefault





if __name__ == '__main__':
    aplication.run(debug=True, port=(5310))