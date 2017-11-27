from flask import render_template, redirect, url_for, request, g, session, jsonify
from app import webapp
import random
import hashlib
import boto3
from boto3.dynamodb.conditions import Key, Attr
import datetime

from twilio.rest import Client
from app import config

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

@webapp.route('/customer', methods=['GET'])
def customer_main():
    """
    Display a page for both login and register as a customer
    :return: a html page
    """
    return render_template("customer_main.html", title="Customer")


@webapp.route('/customer/<customer_name>', methods=['GET'])
def customer_home(customer_name):
    """
    display a list of food trucks to choose
    :param customer_name: the authenticated user
    :return: html
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        session.clear()
        return render_template('access_denied.html')

    # this is the correct customer_foodtruck_list
    table = dynamodb.Table('trucks')
    response = table.scan()
    foodtruck_set = response['Items']
    return render_template("customer_foodtruck_list.html", customer_name=customer_name,
                           foodtruck_set=foodtruck_set)


@webapp.route('/customer/login', methods=['POST'])
def customer_login():
    """
    Log in as a customer
    :return: customer home page
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


# @webapp.route('/customer/register', methods=['POST'])
# def customer_signup():
#     """
#     Sign up as a customer
#     :return: the authenticated customer's home page
#     """
#     username = request.form.get('new_username')
#     pwd = request.form.get('new_password')
#
#     # check length of input
#     error = False
#     if len(username) != 10 or len(pwd)<6 or len(pwd)>20:
#         error=True
#         error_msg = "Error: Invalid Username or Password Length"
#     if error:
#         return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
#                                sign_username=username)
#
#     alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#     numdic = "0123456789"
#     # check if the username is valid
#     for char in username:
#         if char not in numdic:
#             error=True
#             error_msg = "Error: Username Must Be Your 10 Digit Cellphone Number"
#         if error:
#             return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
#                                    sign_username=username)
#
#     # check whether username exists in truck owners table or customers table
#     table = dynamodb.Table('trucks')
#     response = table.query(
#         KeyConditionExpression=Key('truck_username').eq(username)
#     )
#     table2 = dynamodb.Table('customers')
#     response2 = table2.query(
#         KeyConditionExpression=Key('customer_username').eq(username)
#     )
#     error = False
#     if response['Count'] != 0 or response2['Count'] != 0:
#         error = True
#         error_msg = "Error: Username already exists!"
#     if error:
#         return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
#                                    sign_username=username)
#
#     # create a salt value
#     chars=[]
#     for i in range(8):
#         chars.append(random.choice(alphabet))
#     salt = "".join(chars)
#     pwd += salt
#     hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
#     response = table2.put_item(
#         Item={
#             'customer_username': username,
#             'hashed_pwd': hashed_pwd,
#             'salt': salt
#         }
#     )
#     # add to the session
#     session['authenticated'] = True
#     session['username'] = username
#     return redirect(url_for('customer_home', customer_name=username))


# display the menu provided by a particular truck ==> customer_foodtruck_list
@webapp.route('/customer/<customer_name>/<truck_username>', methods=['GET'])
def select_truck(customer_name, truck_username):
    """
    Display the menu that belongs to the selected truck
    :param customer_name: the username of the authenticated user.
    :param truck_username: the selected truck
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        session.clear()
        return render_template('access_denied.html')

    table2 = dynamodb.Table('trucks')
    response2 = table2.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username)
    )
    if response2['Count'] == 0:
        # truck doesn't exist
        redirect(url_for('customer_home', customer_name=customer_name))

    table = dynamodb.Table('menu')
    # get the list of dishes provided by this truck
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username)
    )

    records = []
    for i in response['Items']:
        records.append(i)
    while 'LastEvaluatedKey' in response:
        response = table.query(
            KeyConditionExpression=Key('truck_username').eq(truck_username),
            ExclusiveStartKey=response['LastEvaluatedKey']
        )

        for i in response['Items']:
            records.append(i)

    # display the menu for foodtruck
    return render_template("customer_foodtruck_menu.html", customer_name=customer_name,
                           truck_username=truck_username, dishes=records)


@webapp.route('/customer/<customer_name>/history_orders', methods=['GET'])
def my_history_orders(customer_name):
    """
    Display a list of history orders belonging to the customer
    :param customer_name: the authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        session.clear()
        return render_template('access_denied.html')

    table = dynamodb.Table('orders')
    # retrieve orders in reverse order of finish_time
    response = table.query(
        IndexName='customer_username-finish_time-index',
        KeyConditionExpression=Key('customer_username').eq(customer_name) & Key('finish_time').gt(' '),
        FilterExpression=Attr('history').eq(True),
        ScanIndexForward=False
    )

    return render_template('customer_orders.html', customer_name=customer_name,
                           orders=response['Items'], title='My History Orders')


# display the current on-going orders
@webapp.route('/customer/<customer_name>/ongoing_orders', methods=['GET'])
def my_ongoing_orders(customer_name):
    """
    Display a list of ongoing orders belonging to the customer
    :param customer_name: the authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        session.clear()
        return render_template('access_denied.html')

    table = dynamodb.Table('orders')
    # retrieve orders in order of start_time,
    # orders with history as False are ongoing ones
    # show 'finished' ones and not 'finished' ones in different color
    # 'finished' ones are ones that have 'finish_time' greater than ' '
    # after the customer load this page, the finished ones will go to history orders
    response = table.query(
        IndexName='customer_username-start_time-index',
        KeyConditionExpression=Key('customer_username').eq(customer_name),
        FilterExpression=Attr('finish_time').gt(' ') & Attr('history').eq(False),
        ScanIndexForward=True
    )
    finished = []
    for i in response['Items']:
        finished.append(i)

    while 'LastEvaluatedKey' in response:
        response = table.query(
            IndexName='customer_username-start_time-index',
            KeyConditionExpression=Key('customer_username').eq(customer_name),
            FilterExpression=Attr('finish_time').gt(' ') & Attr('history').eq(False),
            ScanIndexForward=True,
            ExclusiveStartKey=response['LastEvaluatedKey']
        )

        for i in response['Items']:
            finished.append(i)

    response2 = table.query(
        IndexName='customer_username-start_time-index',
        KeyConditionExpression=Key('customer_username').eq(customer_name),
        FilterExpression=Attr('finish_time').eq(' '),
        ScanIndexForward=True
    )
    not_finished = []
    for i in response2['Items']:
        not_finished.append(i)

    while 'LastEvaluatedKey' in response2:
        response2 = table.query(
            IndexName='customer_username-start_time-index',
            KeyConditionExpression=Key('customer_username').eq(customer_name),
            FilterExpression=Attr('finish_time').eq(' '),
            ScanIndexForward=True,
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        for i in response2['Items']:
            not_finished.append(i)

    # change attribute "history" to True for those finished orders, meaning I'm aware that they're completed
    # update_item can only update one item at a time
    for order in finished:
        order_no = order['order_no']
        response3 = table.update_item(
            Key={
                'order_no': order_no
            },
            UpdateExpression="SET history = :value1",
            ExpressionAttributeValues={
                ":value1": True
            }
        )


    # note we are using the same template customer_orders.html
    return render_template('customer_orders.html', customer_name=customer_name,
                           orders=not_finished, finished=finished, title='My Ongoing Orders')


@webapp.route('/customer/<customer_name>/<truck_username>/<dish_name>/<price>/complete', methods=['POST'])
def customer_new_order(customer_name, truck_username, dish_name, price):
    """
    Complete the specific order and put it in history orders
    :param customer_name: the authenticated user
    :param truck_username: the truck that order from
    :param dish_name: the dish that is ordered
    :param price: the unit price of the dish selected
    :return: to ongoing orders
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
        session.clear()
        return render_template('access_denied.html')

    order_count = request.form.get("order_count", "")

    # if order_count == "" or order_count == "0":
    #     print("redirecting to select_truck page")
    #     return redirect(url_for('select_truck',customer_name=customer_name,
    #                             truck_username=truck_username))

    # get # of orders
    # order_count = 0
    # try:
    #     order_count = int(order_count)
    # except:
    #     return redirect(url_for('select_truck',customer_name=customer_name,
    #                             truck_username=truck_username))

    total = str(round(float(order_count) * float(price), 2))
    order_count = int(order_count)
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
            "paid": total,
            "dishes": dishes,
            "history": False,
            "new_order": True
        }
    )

    return redirect(url_for('my_ongoing_orders', customer_name=customer_name))


@webapp.route('/customer/<customer_name>/<truck_username>/<dish_name>/compare', methods=['POST'])
def customer_compare_price(customer_name, truck_username, dish_name):
    """
    
    :param customer_name: 
    :param truck_username: 
    :param dish_name: 
    :return: 
    """
    if 'authenticated' not in session:
        return redirect(url_for('customer_main'))
    if session.get('username', '') != customer_name:
        session.clear()
        return render_template('access_denied.html')

    table = dynamodb.Table('menu')

    response = table.query(
        IndexName='dish_name-truck_username-index',
        KeyConditionExpression=Key('dish_name').eq(dish_name),
        ScanIndexForward=True,
    )

    menu_set = response['Items']

    return render_template('menu_comparison.html', customer_name=customer_name, menu_set=menu_set,
                           truck_username=truck_username)


# perform sanity check for the input first, before going to
# verification step
@webapp.route('/_request_activation/<cell>', methods=['get'])
def request_activation(cell):
    """
    
    :param cell: 
    :return: 
    """
    # username = request.form.get('new_username')
    # pwd = request.form.get('new_password')

    # check cell number
    numdic = "0123456789"
    error = False
    if len(cell) != 10:
        error = True
        error_msg = "Error: Invalid phone number!"
    if error:
        return jsonify(msg=error_msg)

    for char in cell:
        if char not in numdic:
            error=True
            error_msg = "Error: Username must be your 10 digit cellphone number!"
        if error:
            return jsonify(msg=error_msg)

    # check whether username exists in truck owners table or customers table
    table = dynamodb.Table('trucks')
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(cell)
    )
    table2 = dynamodb.Table('customers')
    response2 = table2.query(
        KeyConditionExpression=Key('customer_username').eq(cell)
    )
    error = False
    if response['Count'] != 0 or response2['Count'] != 0:
        error = True
        error_msg = "Error: Username already exists!"
    if error:
        return jsonify(msg=error_msg)

    # here sanity check is done
    send_confirmation_code(cell)
    msg = "Verification code sent! Please check your phone."
    # now go to customer_main_verification html
    return jsonify(msg=msg)


# twilio helper code
def send_confirmation_code(to_number):
    verification_code = generate_code()
    send_sms(to_number, verification_code)
    session['verification_code'] = verification_code
    session['username'] = to_number
    return


def generate_code():
    return str(random.randrange(100000, 999999))


def send_sms(to_number, body):
    account_sid = config.TWILIO_ACCOUNT_SID
    auth_token = config.TWILIO_AUTH_TOKEN
    twilio_number = config.from_twilio_number

    client = Client(account_sid, auth_token)
    client.api.messages.create(to_number,from_=twilio_number,body=body)


@webapp.route('/customer/register', methods=['POST'])
def customer_signup():
    """
    Sign up as a customer
    :return: the authenticated customer's home page
    """
    username = request.form.get('new_username','')
    pwd = request.form.get('new_password','')
    code = request.form.get('verification_code','')

    error = False
    if 'verification_code' not in session or session['verification_code'] != code:
        error = True
        error_msg = "Error: Wrong verification code!"
    if error:
        return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
                               sign_username=username)

    if 'username' not in session or session['username'] != username:
        error = True
        error_msg = "Error: Wrong number!"
    if error:
        return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
                               sign_username=username)

    # check length of input
    if len(pwd)<6 or len(pwd)>20:
        error=True
        error_msg = "Error: Invalid Password Length"
    if error:
        return render_template("customer_main.html", title="Customer Page", signup_error_msg=error_msg,
                               sign_username=username)

    # create a salt value
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars=[]
    for i in range(8):
        chars.append(random.choice(alphabet))
    salt = "".join(chars)
    pwd += salt
    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()

    table2 = dynamodb.Table('customers')

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
    # delete verification code from session
    session.pop('verification_code', None)
    return redirect(url_for('customer_home', customer_name=username))