#from flask_wtf import FlaskForm
#from wtforms import StringField, PasswordField, SubmitField, BooleanField
#from wtforms.validators import DataRequired, Length, Email, EqualTo


#class RegisterForm(FlaskForm):
#   username = StringField('Username', validators=[DataRequired(), Length(min=4, max=15)]) #least number of characters 8 most 30
#   email = StringField('Email', validators=[DataRequired(), Email()])
#   password = PasswordField('Password', validators=[DataRequired()])
#   confirm_password = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('password')])
#   submit = SubmitField('Register')


#class LoginForm(FlaskForm):
#   email = StringField('Email', validators=[DataRequired(), Email()])
#   password = PasswordField('Password', validators=[DataRequired()])
##   remember = BooleanField('Remember me')
#   submit = SubmitField('Login')