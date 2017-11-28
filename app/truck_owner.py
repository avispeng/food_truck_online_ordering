from flask import render_template, redirect, url_for, request, g, session
from app import webapp
import random
import hashlib
import boto3
from boto3.dynamodb.conditions import Key, Attr
import datetime
from app.customer import send_sms


dynamodb = boto3.resource('dynamodb', region_name='us-east-1')


@webapp.route('/owner', methods=['GET'])
def owner_main():
    """
    Display a page for both login and register as a truck owner
    :return: a html page
    """
    return render_template("owner_main.html", title="Truck Owner")


@webapp.route('/owner/login', methods=['POST'])
def owner_login():
    """
    Log in as an owner of the truck
    :return: the authenticated owner's home page
    """
    username = request.form.get('username',"")
    pwd = request.form.get('password',"")
    table = dynamodb.Table('trucks')
    # check if the account exists
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(username)
    )
    error = False
    if response['Count'] == 0:
        error=True
        error_msg = "Error: Username doesn't exist!"
    if error:
        return render_template("owner_main.html",title="Truck Owner", login_error_msg=error_msg, log_username=username)

    # if username exists, is pwd correct?
    salt = response['Items'][0]['salt']
    hashed_pwd = response['Items'][0]['hashed_pwd']

    pwd += salt
    if hashed_pwd == hashlib.sha256(pwd.encode()).hexdigest():
        # login successfully
        # add to the session
        session['authenticated'] = True
        session['username'] = username
        return redirect(url_for('owner_home', truck_username=username))
    else:
        error=True
        error_msg = "Error: Wrong password or username! Please try again!"
    if error:
        return render_template("owner_main.html", title="Truck Owner", login_error_msg=error_msg, log_username=username)


@webapp.route('/owner/register', methods=['POST'])
def owner_signup():
    """
    Sign up as a truck owner
    :return: the authenticated owner's home page
    """
    username = request.form.get('new_username')
    pwd = request.form.get('new_password')

    # check length of input
    error = False
    if len(username)<6 or len(username)>20 or len(pwd)<6 or len(pwd)>20:
        error=True
        error_msg = "Error: Both username and password should have length of 6 to 20!"
    if error:
        return render_template("owner_main.html", title="Truck Owner", signup_error_msg=error_msg,
                               sign_username=username)

    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # check if the username is valid
    for char in username:
        if char not in alphabet:
            error=True
            error_msg = "Error: Username must be combination of characters or numbers!"
        if error:
            return render_template("owner_main.html", title="Truck Owner", signup_error_msg=error_msg,
                                   sign_username=username)

    # check whether username exists in truck owners table or customers table
    table = dynamodb.Table('trucks')
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(username)
    )
    table2 = dynamodb.Table('customers')
    response2 = table2.query(
        KeyConditionExpression=Key('customer_username').eq(username)
    )
    error = False
    if response['Count'] != 0 or response2['Count'] != 0:
        error = True
        error_msg = "Error: Username already exists!"
    if error:
        return render_template("owner_main.html", title="Truck Owner", signup_error_msg=error_msg,
                                   sign_username=username)

    # create a salt value
    chars=[]
    for i in range(8):
        chars.append(random.choice(alphabet))
    salt = "".join(chars)
    pwd += salt
    hashed_pwd = hashlib.sha256(pwd.encode()).hexdigest()
    response = table.put_item(
        Item={
            'truck_username': username,
            'hashed_pwd': hashed_pwd,
            'salt': salt
        }
    )
    # add to the session
    session['authenticated'] = True
    session['username'] = username
    return redirect(url_for('owner_home', truck_username=username))


@webapp.route('/owner/<truck_username>', methods=['GET'])
def owner_home(truck_username):
    """
    Display the menu that belongs to the authenticated truck owner
    :param truck_username: the username of the authenticated user.
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

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

    # get the truck's location and photo
    table2 = dynamodb.Table('trucks')
    response = table2.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username)
    )
    this_owner = response['Items'][0]
    truck_location = this_owner.get('truck_location', '')
    photo = this_owner.get('photo_name', '')
    if truck_location == '':
        truck_location = None
    if photo == '':
        photo = None
    return render_template("owner_home.html", dishes=records, truck_username=truck_username,
                           truck_location=truck_location, photo=photo)


@webapp.route('/logout', methods=['GET'])
def logout():
    """
    Log out from the current account
    :return: welcome page
    """
    # session.pop('username', None)
    session.clear()
    return redirect(url_for('main'))


@webapp.route('/owner/<truck_username>/add_dish', methods=['GET'])
def add_dish(truck_username):
    """
    Enter the page where the truck owner can add a dish to his or her menu
    :param truck_username: authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    return render_template("add_dish.html", title="Add One Dish", truck_username=truck_username)


@webapp.route('/owner/<truck_username>/dish_added', methods=['POST'])
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
        session.clear()
        return render_template('access_denied.html')

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


@webapp.route('/owner/<truck_username>/<dish_name>/delete', methods=['GET'])
def delete_dish(truck_username, dish_name):
    """
    Delete the dish from the owner's menu
    :param truck_username: authenticated user
    :param dish_name: the name of dish to delete
    :return: the owner's home page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    # get image filename from dynamodb
    table = dynamodb.Table('menu')
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username) & Key('dish_name').eq(dish_name)
    )
    if response['Count'] > 0:
        fn = response['Items'][0]['img_filename']
        if fn != 'none.png':
            # delete the image of the dish in s3
            s3 = boto3.resource('s3')
            bucket = s3.Bucket('delicious-dishes')
            response = bucket.delete_objects(
                Delete={
                    'Objects': [
                        {
                            'Key': truck_username+'/'+fn
                        }
                    ]
                }
            )
        # delete the dish in table 'menu' in dynamodb
        response = table.delete_item(
            Key={
                'truck_username': truck_username,
                'dish_name': dish_name
            }
        )
    return redirect(url_for('owner_home', truck_username=truck_username))


@webapp.route('/owner/<truck_username>/history_orders', methods=['GET'])
def history_orders(truck_username):
    """
    Display a list of history orders belonging to the owner
    :param truck_username: the authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    table = dynamodb.Table('orders')
    # retrieve orders in reverse order of finish_time
    response = table.query(
        IndexName = 'truck_username-finish_time-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username) & Key('finish_time').gt(' '),
        # FilterExpression=Attr('finish').eq(True),
        ScanIndexForward=False
    )
    records = []
    for i in response['Items']:
        records.append(i)
    # while 'LastEvaluatedKey' in response:
    #     response = table.query(
    #         IndexName='truck_username-order_no',
    #         KeyConditionExpression=Key('truck_username').eq(truck_username),
    #         ExclusiveStartKey=response['LastEvaluatedKey']
    #         )
    #
    #     for i in response['Items']:
    #         records.append(i)

    return render_template('owner_orders.html', orders=records, title='History Orders', truck_username=truck_username)


@webapp.route('/owner/<truck_username>/ongoing_orders', methods=['GET'])
def ongoing_orders(truck_username):
    """
    Display a list of ongoing orders belonging to the owner
    :param truck_username: the authenticated user
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    table = dynamodb.Table('orders')
    # retrieve orders in order of start_time,
    # orders with blank finish_time are ongoing ones
    # show 'new' ones and not 'new' ones in different color
    # 'new' ones are ones that are going to be shown in this page in the first time
    response = table.query(
        IndexName='truck_username-start_time-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username),
        FilterExpression=Attr('finish_time').eq(' ') & Attr('new_order').eq(False),
        ScanIndexForward=True
    )
    records = []
    for i in response['Items']:
        records.append(i)

    while 'LastEvaluatedKey' in response:
        response = table.query(
            IndexName='truck_username-start_time-index',
            KeyConditionExpression=Key('truck_username').eq(truck_username),
            FilterExpression=Attr('finish_time').eq(' ') & Attr('new_order').eq(False),
            ScanIndexForward=True,
            ExclusiveStartKey=response['LastEvaluatedKey']
            )

        for i in response['Items']:
            records.append(i)


    response2 = table.query(
        IndexName='truck_username-start_time-index',
        KeyConditionExpression=Key('truck_username').eq(truck_username),
        FilterExpression=Attr('finish_time').eq(' ') & Attr('new_order').eq(True),
        ScanIndexForward=True
    )
    records_new = []
    for i in response2['Items']:
        records_new.append(i)

    while 'LastEvaluatedKey' in response2:
        response2 = table.query(
            IndexName='truck_username-start_time-index',
            KeyConditionExpression=Key('truck_username').eq(truck_username),
            FilterExpression=Attr('finish_time').eq(' ') & Attr('new_order').eq(True),
            ScanIndexForward=True,
            ExclusiveStartKey=response2['LastEvaluatedKey']
        )

        for i in response2['Items']:
            records_new.append(i)

    # change attribute "new" to False, meaning they're already checked by the truck owner
    # update_item can only update one item at a time
    for new_order in records_new:
        order_no = new_order['order_no']
        response3 = table.update_item(
            Key={
                'order_no': order_no
            },
            UpdateExpression="SET new_order = :value1",
            ExpressionAttributeValues={
                ":value1": False
            }
        )

    return render_template('owner_orders.html', orders=records, orders_new=records_new, title='Ongoing Orders',
                           truck_username=truck_username)


@webapp.route('/owner/<truck_username>/complete', methods=['POST'])
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
        session.clear()
        return render_template('access_denied.html')

    # retrieve order number from form, and update the table 'orders',
    # fill in the 'finish_time' with current time
    # attribute 'history' will be set to True only when the customer is informed and aware of the complete order
    current = str(datetime.datetime.now())
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

    # send a notification message to the customer's phone
    response2 = table.query(
        KeyConditionExpression=Key('order_no').eq(order_no),
    )
    cell = response2['Items'][0]['customer_username']
    dishes = response2['Items'][0]['dishes']
    msg = "Hey. Your order {0} from {1} is completed. Please have a look at ongoing orders' page.".format(str(dishes), truck_username)
    send_sms(cell, msg)

    return redirect(url_for('ongoing_orders', truck_username=truck_username))


@webapp.route('/owner/<truck_username>/<photo>/show', methods=['GET'])
def show_photo(truck_username, photo):
    """
    display the photo of the truck
    :param truck_username: the authenticated user
    :param photo: the name of the truck's photo
    :return: a html page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    return render_template('truck_photo.html', truck_username=truck_username, photo=photo)




@webapp.route('/owner/<truck_username>/setting', methods=['GET'])
def owner_setting(truck_username):
    """
    Set the photo and the location of the truck
    :param truck_username: the authenticated user
    :return: a setting page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    return render_template('owner_set.html', truck_username=truck_username)


@webapp.route('/owner/<truck_username>/set', methods=['POST'])
def owner_setting_submit(truck_username):
    """
    location and photo are submitted
    :param truck_username: the authenticated user
    :return: home page
    """
    # make sure the user is the one logging in the session
    if 'authenticated' not in session:
        return redirect(url_for('owner_main'))
    if session.get('username', '') != truck_username:
        session.clear()
        return render_template('access_denied.html')

    table = dynamodb.Table('trucks')
    response = table.query(
        KeyConditionExpression=Key('truck_username').eq(truck_username)
    )

    location = request.form.get('location', '')
    # photo = request.files.get('photo_file', '')

    if location != '':
        error = False
        if len(location) > 100:
            error = True
            error_msg = 'Error: Location is too long. Please keep it within 100 characters!'
        if error:
            return render_template('owner_set.html', truck_username=truck_username, error_msg=error_msg, location_set=location)

        alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.#"
        for char in location:
            if char not in alphabet:
                error = True
                error_msg = 'Error: Invalid characters in location!'
            if error:
                return render_template('owner_set.html', truck_username=truck_username, error_msg=error_msg, location_set=location)

        response = table.update_item(
            Key={
                'truck_username': truck_username
            },
            UpdateExpression="SET truck_location = :value1",
            ExpressionAttributeValues={
                ":value1": location
            }
        )

    if 'photo_file' in request.files:
        photo = request.files['photo_file']
        fn = photo.filename
        if fn != '':
            error = False
            allowed_ext = set(['jpg', 'jpeg', 'png', 'gif'])
            if '.' in fn and fn.rsplit('.', 1)[1].lower() in allowed_ext:
                extension = fn.rsplit('.', 1)[1]
                # connect to s3
                s3 = boto3.resource('s3')
                bucket = s3.Bucket('delicious-dishes')

                # upload the photo to s3
                response = bucket.put_object(
                    ACL='public-read',
                    Body=photo,
                    Key=truck_username + '.' + extension
                )
                # add to database
                response = table.update_item(
                    Key={
                        'truck_username': truck_username
                    },
                    UpdateExpression="SET photo_name = :value2",
                    ExpressionAttributeValues={
                        ":value2": truck_username + '.' + extension
                    }
                )
            else:
                error = True
                error_msg = 'Error: Invalid photo format! Please choose from jpg, jpeg, gif, png!'
                if error:
                    return render_template('owner_set.html', truck_username=truck_username, error_msg=error_msg,
                                           location_set=location)

    return redirect(url_for('owner_home', truck_username=truck_username))

#
# @webapp.route('/customer', methods=['GET'])
# def customer_main():
#     return redirect(url_for('main'))


