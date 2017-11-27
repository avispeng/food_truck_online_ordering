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
    table = dynamodb.Table('trucks')
    response = table.scan()
    foodtruck_set = response['Items']
    return render_template("customer_foodtruck_list.html", customer_name=customer_name,
                           foodtruck_set=foodtruck_set)


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
            'customer_username': username,
            'hashed_pwd': hashed_pwd,
            'salt': salt
        }
    )
    # add to the session
    session['authenticated'] = True
    session['username'] = username
    return redirect(url_for('customer_home', customer_name=username))


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
def customer_logout():
    """
    Log out from the current account
    :param truck_username: authenticated user
    :return: welcome page
    """
    # session.pop('username', None)
    session.clear()
    return redirect(url_for('main'))


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
        IndexName='truck_username-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username),
        FilterExpression=Attr('finish_time').eq(' ') & Attr('new_added').eq(False)
                        & Attr('customer_username').eq(customer_name),

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
        IndexName='truck_username-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username) ,

        FilterExpression=Attr('finish_time').eq(' ') & Attr('new_added').eq(True)
                        & Attr('customer_username').eq(customer_name),
        ScanIndexForward=True
    )

    #print("on going order???:\n", response['Items'])

    # note we r using the same template customer_orders.html
    return render_template('customer_orders.html', customer_name=customer_name,
                           orders=response['Items'], title='My Ongoing Orders')


@webapp.route('/customer/<customer_name>/<truck_username>/<dish_name>/complete', methods=['POST'])
def customer_complete_order(customer_name, truck_username, dish_name):
    """
    Complete the specific order and put it in history orders
    :param truck_username: the authenticated user
    :return: to ongoing orders without the order just completed
    """

    # generates a unqiue order id
    def generate_order_id(customer_name):
        cur_time = datetime.datetime.now()
        hstr = customer_name + str(cur_time)
        ho = hashlib.md5(hstr.encode())
        return ho.hexdigest()

    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        return redirect(url_for('customer_home', customer_name=session['username']))
    order_count = request.form.get("order_count", "")
    print("order_count is: ", order_count)

    if order_count == "" or order_count == "0":
        print("redirecting to select_truck page")
        return redirect(url_for('select_truck',customer_name=customer_name,
                                truck_username=truck_username))

    # get # of orders
    order_count = 0
    try:
        order_count = int(order_count)
    except:
        return redirect(url_for('select_truck',customer_name=customer_name,
                                truck_username=truck_username))
    dishes=[]
    while order_count > 0:
        dishes.append(dish_name)
        order_count -= 1

    # order_no is as null
    order_no = ""
    collision = 1
    table = dynamodb.Table('orders')
    while collision > 0:
        # generate a unique order_no, given customer_name and time
        order_no = generate_order_id(customer_name)
        # check if order_no exists ---> collision
        response = table.query(
            KeyConditionExpression=Key('order_no').eq(order_no)
        )
        collision = response['Count']

    # now insert into order table
    start_time = str(datetime.datetime.now())
    # finish_time is " " indicating on going
    response = table.put_item(
        Item={
            'order_no': order_no,
            'start_time': start_time,
            'finish_time': " ",
            "truck_username": truck_username,
            "customer_username": customer_name,
            "paid": "Pending for now?",
            "dishes": dishes,
            "history": False,
            "new_added": True
        }
    )

    print("Debugging response info:\n", response)

    return redirect(url_for('my_ongoing_orders', customer_name=customer_name,
                            truck_username=truck_username))

