#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys

from oauth2client import client
from googleapiclient.discovery import build
import google.oauth2.credentials
from google.cloud import datastore                                 
import google_auth_oauthlib.flow
import tweepy
import configparser
from datetime import datetime, timedelta
import flask
import pytz
import json
import praw
import requests
import xml.etree.ElementTree as ET
from time import sleep


import re

def cleanhtml(raw_html):
  cleanr = re.compile('<.*?>')
  cleantext = re.sub(cleanr, '', raw_html)
  return cleantext


app = flask.Flask(__name__)
app.secret_key = 'tvqAS9c51oVyzHR9pKjL'

def get_last_post(posts, labels):
  startDate = f'{(datetime.now() - timedelta(days=30)).isoformat()}-00:00'
  request = posts.list(blogId='1931799900575633473',labels=labels,startDate=startDate)
  last_post = pytz.utc.localize(datetime.now() - timedelta(days=30)))
  while request != None:
    posts_doc = request.execute()
    if 'items' in posts_doc and posts_doc['items'] is not None:
      for post in posts_doc['items']:
        q_post = datetime.fromisoformat(post['published'])
        if q_post>last_post:
          last_post = q_post
          
    request = posts.list_next(request, posts_doc)
  return last_post

def get_all_tweets(screen_name, last_post):
  # load config
  config = configparser.RawConfigParser()
  config.read('settings.cfg')
  consumer_key = config.get('Twitter OAuth', 'CONSUMER_KEY')
  consumer_secret = config.get('Twitter OAuth', 'CONSUMER_SECRET')
  access_key = config.get('Twitter OAuth', 'ACCESS_TOKEN_KEY')
  access_secret = config.get('Twitter OAuth', 'ACCESS_TOKEN_SECRET')
  
  # auth tweepy
  auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
  auth.set_access_token(access_key, access_secret)
  api = tweepy.API(auth)

  # get tweets and filter to only those after last_post
  alltweets = api.user_timeline(screen_name = screen_name,count=10)
  return [(tweet, api.get_oembed(id=tweet.id)) for tweet in alltweets if pytz.utc.localize(tweet.created_at) > last_post]


@app.route('/')
def main():
  datastore_client = datastore.Client.from_service_account_json('service_account.json') 
  key = datastore_client.key('Task', 'sample_task')   
  task = datastore_client.get(key)  
  # if credentials not initialized, run authorization
  if not task or not task['refresh_token']:
    return flask.redirect('authorize')
  try:
    # reload credentials
    credentials = google.oauth2.credentials.Credentials(**task)
  except:
    return flask.redirect('authorize')

  # Save credentials back to session in case access token was refreshed.
  task.update(credentials_to_dict(credentials))
  datastore_client.put(task)

  service = build('blogger', 'v3', credentials=credentials)
  
  try:
    # get posting service
    posts = service.posts()
    
    #
    # Twitter
    #

    # getting the last twitter post logged on viewfoil
    last_t_post = get_last_post(posts, 'twitter')
    
    # get all tweets after last_post
    tweets = get_all_tweets('bonkerfield', last_t_post + timedelta(minutes=1))
    # transfer each tweet to viewfoil
    for t, emb in tweets:
      print(t.created_at.isoformat())
      body = {
        "title": '🐦',
        "content": emb['html'],
        "published": f"{t.created_at.isoformat()}-00:00",
        "labels": ["twitter"]
        }
      posts.insert(blogId='1931799900575633473', body=body).execute()
      sleep(1)


    #
    # Reddit
    #
    # getting the last reddit post logged on viewfoil
    last_r_post = get_last_post(posts, 'reddit')
    
    # get all reddit posts
    with open('reddit_secrets.json', 'r') as f:
      reddit_secrets = json.load(f)
    reddit = praw.Reddit(client_id=reddit_secrets['client_id'], 
                     client_secret=reddit_secrets['client_secret'],
                     user_agent=reddit_secrets['user_agent'])

    for sub in reddit.redditor('bonkerfield').submissions.new(limit=100):
      created_at = datetime.fromtimestamp(sub.created_utc)
      if pytz.utc.localize(created_at) > last_r_post + timedelta(minutes=1):
        cont = f'<blockquote class="reddit-card"><a href="https://www.reddit.com{sub.permalink}">{sub.title}</a> from <a href="http://www.reddit.com/{sub.subreddit_name_prefixed}">{sub.subreddit_name_prefixed}</a></blockquote>'
        body = {
          "title": '👽',
          "content": cont,
          "published": f"{created_at.isoformat()}-00:00",
          "labels": ["reddit"]
        }
        posts.insert(blogId='1931799900575633473', body=body).execute()
        sleep(1)

    for com in reddit.redditor('bonkerfield').comments.new(limit=100):
      created_at = datetime.fromtimestamp(com.created_utc)
      if pytz.utc.localize(created_at) > last_r_post + timedelta(minutes=1):
        cont = f'<a class="embedly-card" href="https://www.reddit.com{com.permalink}">{com.body}</a>'
        body = {
          "title": '👽',
          "content": cont,
          "published": f"{created_at.isoformat()}-00:00",
          "labels": ["reddit"]
        }
        posts.insert(blogId='1931799900575633473', body=body).execute()
        sleep(1)

    #
    # YouTube
    #

    last_y_post = get_last_post(posts, 'youtube')

    with open('youtube.json', 'r') as f:
      youtube_key = json.load(f)
    youtube = build('youtube','v3',developerKey=youtube_key['api_key']) 

    request = youtube.search().list( 
       part="snippet",  
       channelId="UCjfbKpAq127UVuFeaepkvWg", 
       order="date", 
       publishedAfter=(last_y_post+timedelta(minutes=30)).isoformat()
    ) 
    response = request.execute()

    for item in response['items']:
      if item['id']['kind']=='youtube#video':
        publishedAt = datetime.fromisoformat(item['snippet']['publishedAt'].replace('Z','+00:00' ))
        cont = f'<iframe width="560" height="315" src="https://www.youtube.com/embed/{item["id"]["videoId"]}" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>'
        body = {
          "title": '📺',
          "content": cont,
          "published": f"{publishedAt.isoformat() }",
          "labels": ["youtube"]
        }
        posts.insert(blogId='1931799900575633473', body=body).execute()
        sleep(1)

    #
    # bonkerfield
    #
    
    last_b_post = get_last_post(posts, 'bonkerfield')
    
    resp = requests.get('https://www.bonkerfield.org/feed.xml')
    root = ET.ElementTree(ET.fromstring(resp.content)).getroot()                      

    # walk through feed for new posts
    for item in root.findall('./channel/item'):
      data = {} 
      for child in item: 
        if child.tag == 'pubDate': 
          pubdate = datetime.strptime(child.text[:-6], '%a, %d %b %Y %H:%M:%S')
          if pytz.utc.localize(pubdate) < last_b_post + timedelta(minutes=1):
            break
          data['published'] = pubdate
        else: 
          data[child.tag] = child.text 
      
      if 'link' not in data or 'published' not in data:
        continue
      
      txt = f"<p>{cleanhtml(data['description'].split('</p>')[0])}</p>"
      
      if 'image' in data:
        im_bit = f'<img src="{data["image"]}"/>'
      else:
        im_bit = ''
      cont = f'<a href="{data["link"]}">{im_bit} {txt} <p>... read more on bonkerfield.org</p></a>'
      # append news dictionary to news items list 
      body = {
        "title": data['title'],
        "content": cont,
        "published": f"{data['published'].isoformat()}-00:00",
        "labels": ["bonkerfield"]
      }
      posts.insert(blogId='1931799900575633473', body=body).execute()
      sleep(1)

    return 'Success!'
  
  except client.AccessTokenRefreshError:
    return ('The credentials have been revoked or expired, please re-run'
      'the application to re-authorize')
  
  return 'something went wrong'


@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      'client_secrets.json', scopes=['https://www.googleapis.com/auth/blogger'])

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true',
      prompt='consent')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      'client_secrets.json', scopes=['https://www.googleapis.com/auth/blogger'], state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  credentials = flow.credentials
  datastore_client = datastore.Client.from_service_account_json('service_account.json') 
  key = datastore_client.key('Task', 'sample_task')   
  task = datastore.Entity(key=key) 
 
  task.update(credentials_to_dict(credentials))
  datastore_client.put(task)

  return flask.redirect(flask.url_for('main'))


@app.route('/revoke')
def revoke():
  datastore_client = datastore.Client.from_service_account_json('service_account.json') 
  key = datastore_client.key('Task', 'sample_task')   
  task = datastore_client.get(key)  
  try:
    credentials = google.oauth2.credentials.Credentials(**task)
  except:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')
  datastore_client.delete(key)

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})
  
  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + print_index_table())
  else:
    return('An error occurred.' + print_index_table())


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)