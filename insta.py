# https://towardsdatascience.com/increase-your-instagram-followers-with-a-simple-python-bot-fde048dce20d
from selenium import webdriver
from time import sleep
from random import randint
from googleapiclient import sample_tools


with open('last_insta', 'r') as f:
    last_insta = f.read()
new_last = last_insta
to_post = []
webdriver = webdriver.Chrome(executable_path='/home/stedn/Downloads/chromedriver')
for i in range(1,2):
    webdriver.get('https://www.instagram.com/bonkerfield')
    sleep(randint(1,6))
    post = webdriver.find_element_by_xpath(f'/html/body/div[1]/section/main/div/div[2]/article/div/div/div[1]/div[{i}]/a')
    post.click()
    sleep(randint(1,3))
    dotdotdot = webdriver.find_element_by_xpath('/html/body/div[5]/div[2]/div/article/div[3]/button')
    dotdotdot.click()
    sleep(randint(1,4))
    embed = webdriver.find_element_by_xpath('/html/body/div[6]/div/div/div/button[5]')
    embed.click()
    sleep(randint(2,6))
    txt = webdriver.find_element_by_xpath('/html/body/div[6]/div/div/textarea').text
    dt = txt.split('datetime="')[1].split('"')[0]
    if dt > last_insta:
        to_post.append([dt,txt])
        if dt > new_last:
            new_last = dt
print(to_post)
# upload to blogger
service, flags = sample_tools.init(
    [], 'blogger', 'v3', __doc__, __file__,
    scope='https://www.googleapis.com/auth/blogger')  
blogs = service.blogs() 
posts = service.posts() 
viewfoil = blogs.get(blogId='1931799900575633473').execute()

# transfer each insta to viewfoil
for dt, emb in to_post:
    body = {
    "title": '📷',
    "content": emb,
    "published": dt
    }
    posts.insert(blogId='1931799900575633473', body=body).execute()
    sleep(randint(1,2))

with open('last_insta', 'w') as f:
    f.write(new_last)