from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField(label="Blog Post Title", validators=[DataRequired()])
    subtitle = StringField(label="Subtitle", validators=[DataRequired()])
    img_url = StringField(label="Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField(label="Blog Content", validators=[DataRequired()])
    submit = SubmitField(label="Submit Post")


class RegisterForm(FlaskForm):
    email = StringField(label="E-mail", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    name = StringField(label="Name", validators=[DataRequired()])
    submit = SubmitField(label="Register")


class LoginForm(FlaskForm):
    email = StringField(label="E-mail", validators=[DataRequired(), Email()])
    password = PasswordField(label="password", validators=[DataRequired()])
    submit = SubmitField(label="Log In")


class CommentForm(FlaskForm):
    body = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="SUBMIT COMMENT")
