# import atexit
# from apscheduler.schedulers.background import BackgroundScheduler
# from apscheduler.triggers.interval import IntervalTrigger

from flask import session, jsonify
from app import webapp
import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')


@webapp.route('/_notification', methods= ['GET'])
def notification():
    """
    A scheduled task. Invoked every 1 minute. And send notification to the authenticated user
    :return: jsonified message
    """
    # First, check if the user is logged in
    if 'authenticated' not in session:
        message = " "
    else:
        username = session['username']
        # Second, check the authenticated user is a truck owner or a customer
        table = dynamodb.Table('trucks')
        response = table.query(
            KeyConditionExpression=Key('truck_username').eq(username)
        )
        if response['Count'] != 0:
            # it's a truck owner, check if there are any new orders
            table3 = dynamodb.Table('orders')
            response3 = table3.query(
                IndexName='truck_username-start_time-index',
                KeyConditionExpression=Key('truck_username').eq(username),
                FilterExpression=Attr('new_order').eq(True),
                ScanIndexForward=False  # latest orders come first
            )
            if response3['Count'] > 0:
                # yes there are new orders
                message = "You have new orders. Please take a look at the ongoing orders' page."
            else:
                # no new orders
                message = " "
        else:
            # it's a customer, check if there are any orders just completed
            table3 = dynamodb.Table('orders')
            response3 = table3.query(
                IndexName='customer_username-finish_time-index',
                KeyConditionExpression=Key('customer_username').eq(username) & Key('finish_time').gt(' '),
                FilterExpression=Attr('history').eq(False),
                ScanIndexForward=False  # latest complete orders come first
            )
            if response3['Count'] > 0:
                # yes there are orders just completed
                message = "There are order(s) just completed. Please have a look at ongoing orders' page."
            else:
                # no newly completed orders
                message = " "
    print("refreshed.")
    return jsonify(message=message)


# scheduler = BackgroundScheduler()
# scheduler.start()
# scheduler.add_job(
#     func=notification,
#     trigger=IntervalTrigger(seconds=60),
#     id='orders_status',
#     name='Refresh the pages opened by an authenticated user every 60 seconds',
#     misfire_grace_time=10,
#     coalesce=True,
#     max_instances=1,
#     replace_existing=False)
# # Shut down the scheduler when exiting the app
# atexit.register(lambda: scheduler.shutdown())
