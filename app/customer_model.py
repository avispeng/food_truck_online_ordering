from flask import render_template, redirect, url_for, request, g, session
from app import webapp
import random
import hashlib
import boto3
from boto3.dynamodb.conditions import Key, Attr
import datetime

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

@webapp.route('/customer', methods=['GET'])
def customer_main():
    """
    Display a page for both login and register as a truck owner
    :return: a html page
    """
    return render_template("customer_main.html", title="Customer")


@webapp.route('/customer/<customer_name>', methods=['GET'])
def customer_home(customer_name):
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        return redirect(url_for('customer_home', customer_name=session['username']))

    # this is the correct customer_foodtruck_list
    return render_template("customer_foodtruck_list.html", customer_name=customer_name)



# check if current session is loggedin
def check_authentication(customer_name):
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        return redirect(url_for('customer_home', customer_name=session['username']))




@webapp.route('/customer/login', methods=['POST'])
def customer_login():
    """
    Log in as an owner of the truck
    :return: the authenticated owner's home page
    """
    username = request.form.get('username',"")
    pwd = request.form.get('password',"")
    table = dynamodb.Table('customers')
    # check if the account exists
    response = table.query(
        KeyConditionExpression=Key('customer_username').eq(username)
    )
    error = False
    if response['Count'] == 0:
        error=True
        error_msg = "Error: Username doesn't exist!"
    if error:
        return render_template("customer_main.html",title="Customer Page", login_error_msg=error_msg,
                               log_username=username)

    # if username exists, is pwd correct?
    salt = response['Items'][0]['salt']
    hashed_pwd = response['Items'][0]['hashed_pwd']

    pwd += salt
    if hashed_pwd == hashlib.sha256(pwd.encode()).hexdigest():
        # login successfully
        # add to the session
        session['authenticated'] = True
        session['username'] = username

        # add customer_name for authentication reason
        return redirect(url_for('customer_home', customer_name=username))
    else:
        error=True
        error_msg = "Error: Wrong password or username! Please try again!"
    if error:
        return render_template("customer_main.html", title="Customer Page", login_error_msg=error_msg,
                               log_username=username)


@webapp.route('/customer/register', methods=['POST'])
def customer_signup():
    """
    Sign up as a truck owner
    :return: the authenticated owner's home page
    """
    username = request.form.get('new_username')
    pwd = request.form.get('new_password')

    # check length of input
    error = False
    if len(username) != 10 or len(pwd)<6 or len(pwd)>20:
        error=True
        error_msg = "Error: Invalid Username or Password Length"
    if error:
        return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
                               sign_username=username)

    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numdic = "0123456789"
    # check if the username is valid
    for char in username:
        if char not in numdic:
            error=True
            error_msg = "Error: Username Must Be Your 10 Digit Cellphone Number"
        if error:
            return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
                                   sign_username=username)

    # check whether username exists in customers table
    table2 = dynamodb.Table('customers')
    response2 = table2.query(
        KeyConditionExpression=Key('customer_username').eq(username)
    )
    error = False
    if response2['Count'] != 0:
        error = True
        error_msg = "Error: Username already exists!"
    if error:
        return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
                                   sign_username=username)

    # create a salt value
    chars=[]
    for i in range(8):
        chars.append(random.choice(alphabet))
    salt = "".join(chars)
    pwd += salt
    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
    response = table2.put_item(
        Item={
            'truck_username': username,
            'hashed_pwd': hashed_pwd,
            'salt': salt
        }
    )
    # add to the session
    session['authenticated'] = True
    session['username'] = username
    return redirect(url_for('customer_home', truck_username=username))


# display the menu provided by a particular truck ==> customer_foodtruck_list
@webapp.route('/customer/<customer_name>/<truck_username>', methods=['GET'])
def select_truck(customer_name, truck_username):
    """
    Display the menu that belongs to the authenticated truck owner
    :param truck_username: the username of the authenticated user.
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        return redirect(url_for('customer_home', customer_name=session['username']))

    table = dynamodb.Table('menu')
    # get the list of dishes provided by this truck
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username)
    )

    # sanity check
    if response['Items'] is None:
        print("error: the food truck does not exist: ", truck_username)
        return

    # display the menu for foodtruck
    return render_template("customer_foodtruck_menu.html", customer_name=customer_name,
                           truck_username=truck_username, dishes=response['Items'])


@webapp.route('/customer/logout', methods=['GET'])
def logout():
    """
    Log out from the current account
    :param truck_username: authenticated user
    :return: welcome page
    """
    # session.pop('username', None)
    session.clear()
    return redirect(url_for('main'))


@webapp.route('/<customer>/<truck_username>/<dish_name>/add_dish', methods=['GET'])
def add_dish(customer_name, truck_username, dish_name):
    """
    Enter the page where the truck owner can add a dish to his or her menu
    :param truck_username: authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name :
        return redirect(url_for('select_truck', truck_username=session['username']))



@webapp.route('/customer/<truck_username>/dish_added', methods=['POST'])
def dish_added(truck_username):
    """
    Update the menu with newly added dish
    :param truck_username: authenticated user
    :return: truck owner's home page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        return redirect(url_for('owner_home', truck_username=session['username']))

    dish_name = request.form.get('dish_name', "")
    price = request.form.get('price', "")

    # avoid repeating
    table = dynamodb.Table('menu')
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username) & Key('dish_name').eq(dish_name)
    )
    error = False
    if response['Count'] != 0:
        error = True
        error_msg = "Error: This dish already exists!"
    if error:
        return render_template("add_dish.html", title="Add One Dish", truck_username=truck_username, error_msg=error_msg)

    # connect to s3
    s3 = boto3.resource('s3')
    bucket = s3.Bucket('delicious-dishes')

    if 'photo' in request.files:
        allowed_ext = set(['jpg', 'jpeg', 'png', 'gif'])
        photo = request.files['photo']
        fn = photo.filename
        if '.' in fn and fn.rsplit('.', 1)[1].lower() in allowed_ext:
            # handling filename length
            if len(fn) > 30:
                rez = fn.rsplit('.', 1)
                fn = rez[0][0:26] + "." + rez[1]
            if fn == 'none.png':
                fn = dish_name + '.png'
            # upload the photo to owner's folder in s3
            response = bucket.put_object(
                ACL='public-read',
                Body=photo,
                Key=truck_username + '/' + fn
            )
        else:
            fn = 'none.png'
    else:
        fn = 'none.png'

    if fn == 'none.png':
        # copy none.png on s3 to the target truck owner's folder on s3
        copy_source = {
            'Bucket': 'delicious-dishes',
            'Key': 'none.png'
        }
        bucket.copy(copy_source, truck_username+'/none.png')
        # client = boto3.client('s3')
        # response = client.get_object(
        #     Bucket='delicious-dishes',
        #     Key='none.png'
        # )
        # photo = response['Body']

    # save to dynamodb
    response = table.put_item(
        Item={
            'truck_username': truck_username,
            'dish_name': dish_name,
            'price': price,
            'img_filename': fn
        }
    )
    return redirect(url_for('owner_home', truck_username=truck_username))


@webapp.route('/customer/<customer_name>/<truck_username>/history_orders', methods=['GET'])
def my_history_orders(customer_name, truck_username):
    """
    Display a list of history orders belonging to the owner
    :param truck_username: the authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        return redirect(url_for('customer_home', customer_name=session['username']))

    table = dynamodb.Table('orders')
    # retrieve orders in reverse order of finish_time
    response = table.query(
        IndexName='customer_username-start_time-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username) &
                               Key('customer_username').eq(customer_name),

        FilterExpression=Attr('finish_time').eq(' ') & Attr('new').eq(False),
        ScanIndexForward=True
    )

    return render_template('customer_orders.html', customer_name=customer_name,
                           orders=response['Items'], title='My History Orders')


# display the current on-going orders
@webapp.route('/customer/<customer_name>/<truck_username>/ongoing_orders', methods=['GET'])
def my_ongoing_orders(customer_name, truck_username):
    """
    Display a list of ongoing orders belonging to the owner
    :param truck_username: the authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        return redirect(url_for('customer_home', customer_name=session['username']))

    table = dynamodb.Table('orders')
    # retrieve orders in order of start_time,
    # orders with blank finish_time are ongoing ones
    # show 'new' ones and not 'new' ones in different color
    # 'new' ones are ones that are going to be shown in this page in the first time
    response = table.query(
        IndexName='customer_username-start_time-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username) &
                               Key('customer_username').eq(customer_name),

        FilterExpression=Attr('finish_time').eq(' ') & Attr('new').eq(True),
        ScanIndexForward=True
    )

    # note we r using the same template customer_orders.html
    return render_template('customer_orders.html', customer_name=customer_name,
                           orders=response['Items'], title='My Ongoing Orders')


@webapp.route('/customer/<truck_username>/complete', methods=['POST'])
def complete_order(truck_username):
    """
    Complete the specific order and put it in history orders
    :param truck_username: the authenticated user
    :return: to ongoing orders without the order just completed
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        return redirect(url_for('owner_home', truck_username=session['username']))

    # retrieve order number from form, and update the table 'orders',
    # fill in the 'finish_time' with current time
    # attribute 'history' will be set to True only when the customer is informed and aware of the complete order
    current = datetime.datetime.now()
    order_no = request.form.get('complete',"")
    table = dynamodb.Table('orders')
    response = table.update_item(
        Key={
            'order_no': order_no
        },
        UpdateExpression="SET finish_time = :value1",
        ExpressionAttributeValues={
            ":value1": current
        }
    )
    return redirect(url_for('ongoing_orders', truck_username=truck_username))


