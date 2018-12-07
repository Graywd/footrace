from flask import (
    render_template, redirect, url_for,
    flash, request, current_app, abort
)
from flask_login import login_required, current_user
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, PostForm
from .. import db
from ..models import Permission, Role, User, Post
from ..decorators import admin_required


@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE) and form.validate_on_submit():
        post = Post(body=form.body.data,
                    author=current_user._get_current_object())
        post.save()
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = Post.objects.order_by('-timestamp').paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts,
                           pagination=pagination)


@main.route('/user/<username>')
def user(username):
    user = User.objects(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = Post.objects.order_by('-timestamp').paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts,
                           pagination=pagination)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        current_user.save()
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<string:username>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(username):
    user = User.objects(username=username).first_or_404()
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.objects(name=form.role.data).first()
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        user.save()
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role.name
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/post/<int:sid>')
def post(sid):
    post = Post.objects(sid=sid).first_or_404()
    return render_template('post.html', posts=[post])


@main.route('/edit/<int:sid>', methods=['GET', 'POST'])
@login_required
def edit(sid):
    post = Post.objects(sid=sid).first_or_404()
    if current_user != post.author and not current_user.can(Permission.ADMIN):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        post.save()
        flash('The post has been updated.')
        return redirect(url_for('.post', sid=post.sid))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)
