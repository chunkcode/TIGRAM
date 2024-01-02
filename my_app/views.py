import time
from ipware import get_client_ip
from IPython.lib.display import IFrame
from django.shortcuts import render,redirect,get_object_or_404
from django.views.generic import TemplateView
from django.http import HttpResponse
from django.http import HttpResponseForbidden
from django.http import FileResponse
from knox.models import AuthToken
from knox.settings import CONSTANTS
import piexif
from .models import *
from django.contrib.auth.decorators import login_required
from django.contrib.auth  import login,authenticate,logout
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse,HttpResponseNotFound
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.conf import settings
import os
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import string
import random
import qrcode
from folium import plugins, Map


from django.template.loader import get_template
from django.template.loader import render_to_string
import tempfile
import pdfkit
from django.http import HttpResponse

import pdfkit
from django.contrib.auth.models import Group
from twilio.rest import Client
from twilio.rest import Client
from twilio import twiml
from django.contrib.auth.hashers import make_password

from django.db.models import Q
from django_pdfkit import PDFView
import datetime as datetime
from datetime import timedelta
from datetime import datetime
# import datetime

from django.contrib.auth.backends import ModelBackend
from my_app.models import image_documents
from django.template.loader import get_template
from django.template import Context
import pdfkit
import os
from django.conf import settings
from django.shortcuts import render
import folium
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
import requests
import sweetify





import requests
import hashlib
from django.utils import timezone
import io
import zipfile

import re
import base64
import qrcode
import io


def check_sanitization(*argument2):
 for my_string in argument2:
  print(my_string)
  regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
  if(regex.search(str(my_string).strip()) == None):
    return True
  else:
    return False


  



IMAGE_TAG = {'AadharCard':settings.AADHAR_IMAGE_PATH,'Declaration':settings.DECLARATION_PATH,
			'License':settings.LICENSE_PATH,'LocationSketch':settings.LOCATION_SKETCH_PATH,
			'ProofOfOwnership':settings.PROOF_OF_OWNERSHIP_PATH,'RevenueApplication':settings.REVENUE_APPLICATION_PATH,
			'RevenueApproval':settings.REVENUE_APPROVAL_PATH,'TreeOwnership':settings.TREE_OWNERSHIP_PATH,
			'Signature':settings.SIGN_PATH,'QRCode' :settings.QRCODE_PATH,'Profile':settings.PROFILE_PATH,
			'PhotoProof':settings.PHOTO_PROOF_PATH,'TimberImage':settings.TIMBER_IMAGE

	}

from django.contrib.auth.decorators import user_passes_test
def showurl(request):
	showurlobj=request.get_host()
	return render(request,'view_reports.html',{"displayurl":showurlobj})

def upload_product_image_file(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.PROOF_OF_OWNERSHIP_PATH
	image_path = IMAGE_TAG[image_tag]
	if image_path=='form3':
		image_path = settings.FORM_THREE_FOREST_SIGN
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	# j=random.randint(0,1000)
	# if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]
				#----------------------------------------#

				image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				# from PIL import Image
				# import PIL

				# # creating a image object (main image)
				# im1 = Image.open(post_image)

				# # save a image using extension
				# im1 = im1.save(image_path+"geeks.jpg")
				#------- get content type ----#
				# if file_ext == 'jpg' or file_ext == 'jpeg':
				# 	content_type = 'image/jpeg'
				# if file_ext == 'png':
				# 	content_type = 'image/png'
				# if file_ext == 'gif':
				# 	content_type = 'image/gif'
				# if file_ext == 'svg':
				# 	content_type = 'image/svg+xml'

				#------------ STORE INVOICE --------------#
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name

def upload_timber_image_file(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.TIMBER_IMAGE
	image_path = IMAGE_TAG[image_tag]
	image_name = None
	# j=random.randint(0,1000)
	# if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]
				#----------------------------------------#

				image_name =image_tag+"_"+str(record_id)+"_image_"+str(file_ext)
				imagefile = str(image_path)+str(image_name)

				#------------ STORE INVOICE --------------#
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name

class MobilePhoneOrEmailModelBackend(ModelBackend):

    def authenticate(self, username=None, password=None):
        # the username could be either one of the two
        if '@' in username:
            kwargs = {'email': username}
        else:
            kwargs = {'mobile_phone': username}
        try:
            user = CustomUser.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            return None

    def get_user(self, username):
        try:
            return CustomUser.objects.get(pk=username)
        except CustomUser.DoesNotExist:
            return None

def group_required(*group_names):
    """Requires user membership in at least one of the groups passed in."""
    def in_groups(u):
        if u.is_authenticated:
            if bool(u.groups.filter(name__in=group_names)) | u.is_superuser:
                return True
        return False

    return user_passes_test(in_groups, login_url='index')
    # return HttpResponseNotFound('<h1>Page Not Found! </h1>')




def check_brute(request):
    if "load_count" in request.session:
     count = request.session["load_count"] + 1
    else:
     count = 1
    request.session["load_count"] = count
    try:
     a = LoginAttempts.objects.get(ip= request.session.session_key)
     if a:
      if a.attempts > 5:
        pig1 = a.last_tried.astimezone()
        pig2 = datetime.now()
        s = str(pig1.time()) 
        e = str(pig2.time()) 
        start = datetime.strptime(s[:-7], "%H:%M:%S")  
        end = datetime.strptime(e[:-7], "%H:%M:%S") 
        difference = end - start 
        seconds = difference.total_seconds() 
        minutes = seconds / 60
        if minutes>5:
            return True 
        else:
            return False
      else:
         a.attempts = count
         a.save()
         return True   
    except:
      b = LoginAttempts()
      b.ip = request.session.session_key
      b.attempts = count
      b.save()
      return True
def group_permissions(*group_names):
    """Requires user membership in at least one of the groups passed in."""
    def has_permission(u):
        if u.is_authenticated:
            # if bool(u.groups.filter(name__in=group_names)) | u.is_superuser:
            group_id = u.groups.values('id')
            if bool(RolePermission.objects.filter(method__method_name__in=group_names,group=group_id[0]['id'])) | u.is_superuser:
                return True
        return False

    return user_passes_test(has_permission, login_url='index')





def load_tree_species():
	trees = TreeSpecies.objects.all().values_list('name',flat=True)
	return trees

def is_user(user):
    return user.groups.filter(name='user').exists()



def is_staff_member(user,role_name):
	user_role={
	'revenue_officer':'revenue officer',
	'deputy_range_officer':'deputy range officer',
	'forest_range_officer':'forest range officer',
	'division_officer':'division officer',
	'field_officer':'field officer',
	'state_officer':'state officer',
	'checkpost_officer':'checkpost officer'

	}
	groups=user.groups.values_list('name',flat = True)
	if groups[0] == user_role[role_name]:
			return True
	return False
    # return user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer','division officer','field officer','state officer']).exists()

def is_admin(user):
    return user.groups.filter(name__in=['admin']).exists()
from django.views.decorators.cache import never_cache


@never_cache
def user_login(request):
 context = {}
 if request.user.is_authenticated:
  return HttpResponseRedirect(reverse('index'))
 if request.method == 'POST':
  if check_brute(request) == False:
    context["message"] = "Please wait for 5 minutes !"
    return render(request,'my_app/tigram/ulogin.html',context)
  
  username = request.POST.get('uname')
  password = request.POST.get('psw')
  if '@' in username:
   user = authenticate(request,email=username,password=password)
   if user:
    if is_user(user)!=True:
     context["message"] = "Provide valid credentials !"
     return render(request,'my_app/tigram/ulogin.html',context)
    login(request,user)
    user_details=CustomUser.objects.filter(id=request.user.id,mobile_verified = "True").values('name','user_id')
    request.session['username'] = user_details[0]['name']
    request.session['useremail'] = username
    request.session['userid'] =  user_details[0]['user_id']
    groups=request.user.groups.values_list('name',flat = True)
    if 'user' in groups:
     return HttpResponseRedirect(reverse('dashboard'))
    elif 'officer' in groups:
     return HttpResponseRedirect(reverse('officer_dashboard'))
    else:
     return HttpResponseRedirect(reverse('officer_dashboard'))
   else:
    context["message"] = "Provide valid credentials !"
    return render(request,'my_app/tigram/ulogin.html',context)

		# else:
		# 	# username =
		# 	eml=""
		# 	em = CustomUser.objects.filter(phone=username).values('email')
		# 	if em:

		# 		eml= em[0]["email"]
		# 	else:
		# 		eml=""
		# 	user = authenticate(email=eml,password=password)
		# 	if user:
		# 		if is_user(user)!=True:
		# 			context["message"] = "Provide valid credentials !"
		# 			return render(request,'my_app/tigram/ulogin.html',context)
		# 		login(request,user)
		# 		groups=request.user.groups.values_list('name',flat = True)
		# 		if 'user' in groups:
		# 			return HttpResponseRedirect(reverse('dashboard'))
		# 		elif 'officer' in groups:
		# 			# kwargs={'prod': prod})
		# 			return HttpResponseRedirect(reverse('officer_dashboard'))
		# 		else:
		# 			return HttpResponseRedirect(reverse('officer_dashboard'))
		# 	else:
		# 		context["message"] = "Provide valid credentials !"
		# 		return render(request,'my_app/tigram/ulogin.html',context)
 elif request.method == 'GET':
  login_type = request.GET.get('login_type')
  if login_type == 'officer':
   return render(request,'my_app/tigram/officerlogin.html',context)
  else:
   return render(request,'my_app/tigram/ulogin.html',context)
 else:
  pass
 return render(request,'my_app/tigram/ulogin.html',context)




























































































@never_cache
def staff_login(request,role_name=''):
 context = {}
 if role_name=='':
  role_name='no_user_found'
 context["role_name"]=role_name
 context["group_roles"] = Group.objects.values('name').filter(is_delete=False,name__in=['revenue officer','deputy range officer','forest range officer','division officer','field officer','state officer','checkpost officer'])
 if request.user.is_authenticated: 
  return HttpResponseRedirect(reverse('index'))
 if request.method == 'POST':
  if check_brute(request) == False:
   context["message"] = "Please wait for 5 minutes !"
   return render(request,'my_app/tigram/ulogin.html',context)
  if role_name=='no_user_found':
   selected_role_name=request.POST.get('selected_role_name',None)
   role_name=selected_role_name.replace(' ', '_') if selected_role_name != None else 'no_user_found'
  context["role_name"]=role_name
  username = request.POST.get('uname')
  password = request.POST.get('psw')
  if '@' in username:
   user = authenticate(request,email=username,password=password)
   if user:
    if role_name!='no_user_found':
     if is_staff_member(user,role_name)!=True:
      context["message"] = "Provide valid credentials !"
      context["role_name"]=role_name
      context["response_code"]="error"
      return render(request,'my_app/tigram/officerlogin.html',context)
     login(request,user)
     groups=request.user.groups.values_list('name',flat = True)
     if 'user' in groups:
      return HttpResponseRedirect(reverse('dashboard'))
     elif 'officer' in groups:
      return HttpResponseRedirect(reverse('officer_dashboard'))
     else:
      if role_name=='checkpost_officer':
       return HttpResponseRedirect(reverse('Scaned'))
      else:
       return HttpResponseRedirect(reverse('officer_dashboard'))
   else:
    context["role_name"]=role_name
    context["message"] = "Provide valid credentials !"
    context["response_code"]="error"
    return render(request,'my_app/tigram/officerlogin.html',context)
  else:
   eml=""
   em = CustomUser.objects.filter(phone=username).values('email')
   if em:
    eml= em[0]["email"]
   else:
    eml=""
    user = authenticate(email=eml,password=password)
    if user:
     if is_staff_member(user,role_name)!=True:
      context["message"] = "Provide valid credentials !"
      context["role_name"]=role_name
      return render(request,'my_app/tigram/officerlogin.html',context)
     login(request,user)
     groups=request.user.groups.values_list('name',flat = True)
     if 'user' in groups:
      return HttpResponseRedirect(reverse('dashboard'))
     elif 'officer' in groups:
      return HttpResponseRedirect(reverse('officer_dashboard'))
     else:
      return HttpResponseRedirect(reverse('officer_dashboard'))
    else:
     context["message"] = "Provide valid credentials !"
     return render(request,'my_app/tigram/officerlogin.html',context)

 elif request.method == 'GET':
  return render(request,'my_app/tigram/officerlogin.html',context)
 else:
  pass
 return render(request,'my_app/tigram/officerlogin.html',context)
@never_cache

def super_login(request):
	login(request,user)
	groups=request.user.groups.values_list('name',flat = True)
	return HttpResponseRedirect(reverse('admin_dashboard'))
@never_cache
def admin_login(request):
 context = {}
 if request.user.is_authenticated:
  return HttpResponseRedirect(reverse('index'))
 if request.method == 'POST':
  username = request.POST.get('uname')
  password = request.POST.get('psw')
  user = authenticate(request,email=username,password=password)
  if user:
   if user.is_superuser :
    login(request,user)
    return HttpResponseRedirect(reverse('admin_dashboard'))
   else:
    context["message"] = "Invalid credentials !"
    return render(request,'my_app/tigram/admin/login.html',context)
  else:
   context["message"] = "Provide valid credentials !"
   return render(request,'my_app/tigram/admin/login.html',context)
 elif request.method == 'GET':
  return render(request,'my_app/tigram/admin/login.html',context)
 return render(request,'my_app/tigram/admin/login.html',context)


@login_required(login_url='staff_login')

@group_permissions('officer_dashboard')
def officer_dashboard(request):
 context = {}
 context['area_range_name']=''
 groups=request.user.groups.values_list('name',flat = True)
 application = Applicationform.objects.all()
 scan_details = ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id)
 
 if groups[0] == "revenue officer":
  urange = RevenueOfficerdetail.objects.get(Rev_user = request.user.id)
 else:
  urange=ForestOfficerdetail.objects.get(fod_user_id=request.user.id)

 transit = []
 for i in application:
    if i.area_range == urange.range_name.name:
        ad = TransitPass.objects.filter(app_form=i,transit_status="Pending")
        if ad:
         transit.append(ad)
 context['transit'] = transit

 context['group'] = groups[0]
 context['current_page']='dashboard'
 if context['group'] == 'division officer':
 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id).values_list('division_name',flat=True)
 	div_name1 = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id).values_list('division_name_id__name',flat=True)
 	context['area_range'] =Range.objects.filter(division_id=div_name[0]).distinct().values_list('name',flat=True)
 elif context['group'] == 'state officer':
 	context['division_name'] = Division.objects.filter(is_delete=False).values_list('name',flat=True)
 	context['area_range'] =Range.objects.filter(is_delete=False).distinct().values_list('name',flat=True)
 
 	context['area_div_name']=request.GET.get('div_name',None)
 	context['area_div_name']= "" if context['area_div_name'] == "" or context['area_div_name']==None else context['area_div_name']
 	area_div_name = context['area_div_name']
 	if area_div_name!=None:
 		if area_div_name.isdigit():
 			context['area_range'] = Range.objects.filter(division_id=area_div_name,is_delete=False).distinct().values_list('name',flat=True)
 		else:
 			context['area_range'] = Range.objects.filter(division__name__iexact=area_div_name,is_delete=False).distinct().values_list('name',flat=True)
 	if len(context['area_range'])<1 and area_div_name=="" or area_div_name==None:
 		context['area_range'] = Range.objects.filter(is_delete=False).values_list('name',flat=True)
 else:
 	pass
 if groups[0] =='revenue officer':
 	context['text_show'] = 'Revenue Officer'
 	rev_range=RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
 	if not rev_range :
 		return HttpResponseRedirect(reverse('index'))
 	pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(verify_office=False,area_range=rev_range[0].range_name.name,is_noc=False).order_by('-id')
 	# approved_list = application.filter(verify_office=True,area_range=rev_range[0].range_name.name,deemed_approval=False).order_by('-id')
 	approved_list = application.filter(area_range=rev_range[0].range_name.name,deemed_approval=False,is_noc=False,verify_office=True).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P')).order_by('-id')
 	deemed_approved_list =application.filter(deemed_approval=True,area_range=rev_range[0].range_name.name).order_by('-id')
 	noc_list =application.filter(is_noc=True,area_range=rev_range[0].range_name.name).order_by('-id')
 
 elif groups[0] =='deputy range officer':
 	context['text_show'] = 'Deputy Range Officer'
 	urange=ForestOfficerdetail.objects.filter(fod_user_id=request.user.id) 
 	if not urange :
 		return HttpResponseRedirect(reverse('index'))
 	pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(depty_range_officer=False,area_range=urange[0].range_name.name,is_noc=False,d = request.user).order_by('-id')
 	#approved_list = application.filter(depty_range_officer=True,area_range=urange[0].range_name.name,deemed_approval=False).order_by('-id')
 	approved_list = application.filter(Q(Q(application_status='A')|Q(application_status='R')),area_range=urange[0].range_name.name,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P')).order_by('-id')
 	deemed_approved_list =application.filter(deemed_approval=True,area_range=urange[0].range_name.name).order_by('-id')
 	noc_list =application.filter(is_noc=True,area_range=urange[0].range_name.name).order_by('-id')
 	# application = application.filter(verify_office=True)
 elif groups[0] =='forest range officer':
 	context['text_show'] = 'Forest Range Officer'
 	urange=ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
 	if not urange :
 		return HttpResponseRedirect(reverse('index'))
 	pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(verify_range_officer=False,area_range=urange[0].range_name.name,is_noc=False).order_by('-id')
 	# approved_list = application.filter(application_status='A').filter(verify_range_officer=True,area_range=urange[0].range_name.name,deemed_approval=False).order_by('-id')
 	approved_list = application.filter(Q(Q(application_status='A')|Q(application_status='R')),area_range=urange[0].range_name.name,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P')).order_by('-id')
 	deemed_approved_list =application.filter(deemed_approval=True,area_range=urange[0].range_name.name).order_by('-id')
 	noc_list  = application.filter(is_noc=True,area_range=urange[0].range_name.name).order_by('-id') 
 	# application = application.filter(depty_range_officer=True)
 
 elif groups[0] == 'checkpost officer':
 	context['text_show'] = 'checkpost officer'
 	urange = CheckPostOfficerdetail.objects.filter(check_user_id=request.user.id)
 	if not urange:
 		return HttpResponseRedirect(reverse('index'))
 	pending_list = application.exclude(Q(application_status='L')|Q(application_status='A') | Q(application_status='R')).filter(verify_range_officer=False, area_range=urange[0].range_name.name, is_noc=False).order_by('-id')
 	approved_list = application.filter(application_status='A').filter(verify_range_officer=True,area_range=urange[0].range_name.name,deemed_approval=False).order_by('-id')
 	approved_list = application.filter(Q(Q(verify_range_officer=True) | Q(Q(verify_forest1=True),Q(Q(application_status='A') | Q(application_status='R')))),area_range=urange[0].range_name.name, deemed_approval=False,is_noc=False).filter(Q(application_status='A') | Q(application_status='R') | Q(application_status='P')).order_by('-id')
 	deemed_approved_list = application.filter(deemed_approval=True, area_range=urange[0].range_name.name).order_by('-id')
 	noc_list = application.filter(is_noc=True, area_range=urange[0].range_name.name).order_by('-id')
 	scan_details= ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id)
 # application = application.filter(depty_range_officer=True)
 
 elif  groups[0] =='division officer':
 	context['text_show'] = groups[0]
 	area_range_name = request.GET.get('range_name')
 	if area_range_name=="" or area_range_name == None:
 		pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(division__icontains=div_name1[0]).order_by('-id')
 		approved_list = application.filter(deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P',other_state=False)).filter(division__icontains=div_name1[0]).order_by('-id')
 		deemed_approved_list =application.filter(deemed_approval=True).filter(division__icontains=div_name1[0]).order_by('-id')
 		noc_list =application.filter(is_noc=True).filter(division__icontains=div_name1[0]).order_by('-id')
 	else:
 		context['area_range_name']=area_range_name
 		pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(area_range__icontains=area_range_name).order_by('-id')
 		approved_list = application.filter(deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P',other_state=False),area_range__icontains=area_range_name).order_by('-id')
 		deemed_approved_list =application.filter(deemed_approval=True,area_range__icontains=area_range_name).order_by('-id')
 		noc_list =application.filter(is_noc=True,area_range__icontains=area_range_name).order_by('-id')
 elif groups[0] =='admin' or groups[0] =='state officer':
 	context['text_show'] = groups[0]
 	area_range_name = request.GET.get('range_name')
 	# context['area_div_name']=request.GET.get('div_name',None)
 	# area_div_name = context['area_div_name']
 	if area_div_name != None:
 		if area_div_name.isdigit():
 			context['area_range'] = Range.objects.filter(division_id=area_div_name,is_delete=False).values_list('name',flat=True)
 		else:
 			context['area_range'] = Range.objects.filter(division__name__iexact=area_div_name,is_delete=False).values_list('name',flat=True)
 	if len(context['area_range'])<1 and area_div_name=="" or area_div_name==None:
 			context['area_range'] = Range.objects.filter(is_delete=False).values_list('name',flat=True)
 
 	# div_id=context['area_div_name']
 
 	if area_div_name == "" or area_div_name == None:
 		if area_range_name=="" or area_range_name == None:
 			pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).order_by('-id')
 			approved_list = application.filter(deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P',other_state=False)).order_by('-id')
 			deemed_approved_list =application.filter(deemed_approval=True).order_by('-id')
 			noc_list =application.filter(is_noc=True).order_by('-id')
 		else:
 			context['area_range_name']=area_range_name
 			pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(area_range__icontains=area_range_name).order_by('-id')
 			approved_list = application.filter(deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P',other_state=False),area_range__icontains=area_range_name).order_by('-id')
 			deemed_approved_list =application.filter(deemed_approval=True,area_range__icontains=area_range_name).order_by('-id')
 			noc_list =application.filter(is_noc=True,area_range__icontains=area_range_name).order_by('-id')
 	else:
 		if area_range_name=="" or area_range_name == None:
 			pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(division__icontains=area_div_name).order_by('-id')
 			approved_list = application.filter(deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P',other_state=False),division__icontains=area_div_name).order_by('-id')
 			deemed_approved_list =application.filter(deemed_approval=True,division__icontains=area_div_name).order_by('-id')
 			noc_list =application.filter(is_noc=True,division__icontains=area_div_name).order_by('-id')
 		else:
 			context['area_range_name']=area_range_name
 			pending_list = application.exclude(Q(application_status='L')|Q(application_status='A')|Q(application_status='R')|Q(application_status='I')).filter(area_range__icontains=area_range_name,division__icontains=area_div_name).order_by('-id')
 			approved_list = application.filter(deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P',other_state=False),area_range__icontains=area_range_name,division__icontains=area_div_name).order_by('-id')
 			deemed_approved_list =application.filter(deemed_approval=True,area_range__icontains=area_range_name,division__icontains=area_div_name).order_by('-id')
 			noc_list =application.filter(is_noc=True,area_range__icontains=area_range_name,division__icontains=area_div_name).order_by('-id')
 else:
 	return HttpResponseRedirect(reverse('index'))
 	context['text_show'] = 'Admin'
 # approved_list = application.filter(application_status='A').order_by('-id')
 context['user'] = request.user
 # context['application']
 # applicant = []
 # incr = 1
 # for each in application:
 # 	checkstatus = {}
 # 	checkstatus['sr'] =incr
 # 	checkstatus['applicant_no'] = each.id
 # 	checkstatus['application_no'] = each.application_no
 # 	checkstatus['applicant_name'] = each.name
 # 	checkstatus['created_date'] = each.created_date
 # 	checkstatus['application_status'] = each.get_application_status_display()
 # 	checkstatus['verification_status'] =each.application_status
 
 # 	# checkstatus['current_status'] =each.application_status
 
 # 	if each.reason_range_officer != '':
 # 		checkstatus['remark'] =  each.reason_range_officer
 # 		checkstatus['remark_date']= each.range_officer_date
 # 	elif each.reason_depty_ranger_office != '':
 # 		checkstatus['remark'] =  each.reason_depty_ranger_office
 # 		checkstatus['remark_date']= each.deputy_officer_date
 # 	elif each.reason_office != '':
 # 		checkstatus['remark'] =  each.reason_office
 # 		checkstatus['remark_date']= each.verify_office_date
 # 	else:
 # 		checkstatus['remark'] =  'N/A'
 # 		checkstatus['remark_date']= 'N/A'
 # 	if each.verify_range_officer == True:
 # 		checkstatus['current_status'] = 'Approved by Forest Range Officer' if each.application_status == 'A' else 'Rejected by Forest Range Officer'
 # 		checkstatus['current_status_by'] ='forest range officer'
 # 	elif each.depty_range_officer == True :
 # 		checkstatus['current_status'] =  'Approved by Deputy Range Officer and Forest Range Officer Approval Pending' if each.application_status == 'A' else 'Rejected by Deputy Range Officer'
 # 		checkstatus['current_status_by'] ='deputy range officer'
 # 	elif each.verify_office == True  :
 # 		checkstatus['current_status'] = 'Approved by Revenue Officer and Deputy Range Officer Approval Pending' if each.application_status == 'A' else 'Rejected by Revenue Officer'
 # 		checkstatus['current_status_by'] ='revenue officer'
 # 	else:
 # 		# checkstatus['current_status'] ='Revenue Officer Approval Pending'
 # 		checkstatus['current_status'] = 'Rejected by Revenue Officer' if each.application_status == 'R' else 'Revenue Officer Approval Pending'
 # 	checkstatus['query'] = ''
 # 	checkstatus['tp_issue_date'] = each.transit_pass_created_date if each.application_status == 'A' else 'N/A'
 # 	checkstatus['tp_number'] = each.transit_pass_id
 # 	# if each.application_status != 'Approved':
 # 	# 	checkstatus['current_status'] ='Rejected'
 # 	# tp = TransitPass.objects.filter(app_form__by_user_id=each.id).order_by('-app_form_id')
 # 	applicant.append(checkstatus)
 # 	incr = incr+1
 # context['application'] = applicant
 pending_applicant = []
 incr1 = 1
 pending_application_names=[]
 pending_application_dates=[]
 pending_application_no=[]
 for each in pending_list:
 	checkstatus = {}
 	checkstatus['sr'],checkstatus['approved_by_r'] =incr1 , each.approved_by_r
 	checkstatus['applicant_no']= each.id 
 	checkstatus['application_no'] = each.application_no
 	checkstatus['applicant_name']  , checkstatus['current_app_status'] =  each.name,each.current_app_status
    
 	checkstatus['created_date'] = each.created_date
 	checkstatus['application_status'] = each.get_application_status_display()
 	checkstatus['verification_status'] =each.application_status
 	checkstatus['depty_range_officer'] ,checkstatus['d'] = each.depty_range_officer,each.d_id
 	pending_application_names.append(checkstatus['applicant_name'])
 	pending_application_dates.append(checkstatus['created_date'])
 	pending_application_no.append(checkstatus['application_no'])
 
 	# checkstatus['current_status'] =each.application_status
 	# checkstatus['days_left_for_approval'] = check
 	if each.reason_division_officer != '':
 		checkstatus['remark'] =  each.reason_division_officer
 		checkstatus['remark_date']= each.division_officer_date
 	elif each.reason_range_officer != '':
 		checkstatus['remark'] =  each.reason_range_officer
 		checkstatus['remark_date']= each.range_officer_date
 	elif each.reason_depty_ranger_office != '':
 		checkstatus['remark'] =  each.reason_depty_ranger_office
 		checkstatus['remark_date']= each.deputy_officer_date
 	elif each.reason_forest1 != '':
 		checkstatus['remark'] =  each.reason_forest1
 		checkstatus['remark_date']= each.forest1_date
 	elif each.reason_deputy2 != '':
 		checkstatus['remark'] =  each.reason_deputy2
 		checkstatus['remark_date']= each.deputy2_date
 	elif each.reason_office != '':
 		checkstatus['remark'] =  each.reason_office
 		checkstatus['remark_date']= each.verify_office_date
 	else:
 		checkstatus['remark'] =  'N/A'
 		checkstatus['remark_date']= 'N/A'
 	if each.application_status == 'R' :
 		checkstatus['remark'] = 'N/A'
 	checkstatus['assigned_deputy'] =  'N/A'
 	if each.is_form_two == True:
 		if each.assigned_deputy2 !=None:
 			checkstatus['assigned_deputy']=each.assigned_deputy2.name
 		elif each.assigned_deputy1 !=None :
 			checkstatus['assigned_deputy']='Yet to Assign for Stage 2' if each.log_updated_by_user ==True else each.assigned_deputy1.name
 		else:
 			checkstatus['assigned_deputy']= 'Yet to Assign for Stage 1'
 	
 	if each.verify_office != True  :
 		checkstatus['days_left_for_approval'] = 'Not Generated'
 		# checkstatus['verification_status'] =each.get_application_status_display()
 	else:
 		days_left=21-(date.today()-each.verify_office_date).days
 		if days_left<1:
 			checkstatus['days_left_for_approval'] = 0 #'TransitPass Expired'
 			# checkstatus['verification_status'] ='TransitPass Expired'
 		else:
 			checkstatus['days_left_for_approval'] = 'Application Expired' if each.application_status == 'R' else days_left
 			# checkstatus['verification_status'] =each.get_application_status_display()
 	checkstatus['query'] = ''
 	checkstatus['tp_issue_date'] = each.transit_pass_created_date if each.application_status == 'A' else 'N/A'
 	checkstatus['tp_number'] = each.transit_pass_id
 	checkstatus['deputy_edit'] = False if each.depty_range_officer == True else True
 	checkstatus['is_form_two'] =each.is_form_two

    
 	pending_applicant.append(checkstatus)
 	incr1 = incr1+1
 context['pending_applicant'] = pending_applicant
 approved_applicant = []
 incr2 = 1
 approved_application_no=[]
 approved_application_names=[]
 approved_application_dates=[]
 for each in approved_list:
 	checkstatus = {}
 	checkstatus['sr'] =incr2
 	checkstatus['applicant_no'] = each.id
 	checkstatus['application_no'] = each.application_no
 	checkstatus['depty_range_officer'] = each.depty_range_officer
 	checkstatus['applicant_name'] , checkstatus['current_app_status'] =  each.name,each.current_app_status  
 	checkstatus['created_date'] = each.created_date
 	checkstatus['application_status'] = each.get_application_status_display()
 
 	# pending_application_names.append(checkstatus['applicant_name'])
 	approved_application_names.append(checkstatus['applicant_name'])
 	approved_application_dates.append(checkstatus['created_date'])
 	approved_application_no.append(checkstatus['application_no'])
 
 	# checkstatus['current_status'] =each.application_status
 
 	if each.reason_division_officer != '':
 		checkstatus['remark'] =  each.reason_division_officer
 		checkstatus['remark_date']= each.division_officer_date
 	elif each.reason_range_officer != '':
 		checkstatus['remark'] =  each.reason_range_officer
 		checkstatus['remark_date']= each.range_officer_date
 	elif each.reason_depty_ranger_office != '':
 		checkstatus['remark'] =  each.reason_depty_ranger_office
 		checkstatus['remark_date']= each.deputy_officer_date
 	elif each.reason_forest1 != '':
 		checkstatus['remark'] =  each.reason_forest1
 		checkstatus['remark_date']= each.forest1_date
 	elif each.reason_deputy2 != '':
 		checkstatus['remark'] =  each.reason_deputy2
 		checkstatus['remark_date']= each.deputy2_date
 	elif each.reason_office != '':
 		checkstatus['remark'] =  each.reason_office
 		checkstatus['remark_date']= each.verify_office_date
 	else:
 		checkstatus['remark'] =  'N/A'
 		checkstatus['remark_date']= 'N/A'
 	if each.application_status == 'R' :
 		checkstatus['remark'] = 'N/A'
 	checkstatus['assigned_deputy'] =  'N/A'
 	if each.is_form_two == True:
 		if each.assigned_deputy2 !=None:
 			checkstatus['assigned_deputy']=each.assigned_deputy2.name
 		elif each.assigned_deputy1 !=None :
 			checkstatus['assigned_deputy']='Yet to Assign for Stage 2' if each.log_updated_by_user ==True else each.assigned_deputy1.name
 		else:
 			checkstatus['assigned_deputy']= 'Yet to Assign for Stage 1'
 	checkstatus['query'] = ''
 	checkstatus['tp_issue_date'] = each.transit_pass_created_date if each.application_status == 'A' else 'N/A'
 	checkstatus['tp_number'] = each.transit_pass_id
 	checkstatus['is_form_two'] =each.is_form_two
 	checkstatus['can_apply3']=False
 	if each.is_form_two == True:
 		if each.other_state == True:
 			checkstatus['can_apply3']=True if each.division_officer==True and each.application_status != 'R' else False
 		else:
 			checkstatus['can_apply3']=True if each.verify_range_officer==True and each.application_status != 'R' else False
 	# if each.application_status != 'Approved':
 	# 	checkstatus['current_status'] ='Rejected'
 	# tp = TransitPass.objects.filter(app_form__by_user_id=each.id).order_by('-app_form_id')
 	approved_applicant.append(checkstatus)
 	incr2 = incr2+1
 
 # deemed_approved_list
 deemed_approved_applicant = []
 incr3 = 1
 deemed_approved_application_no=[]
 deemed_approved_application_names=[]
 deemed_approved_application_dates=[]
 for each in deemed_approved_list:
 	checkstatus = {}
 	checkstatus['sr'] =incr3
 	checkstatus['applicant_no'] = each.id
 	checkstatus['application_no'] = each.application_no
 	checkstatus['applicant_name'] , checkstatus['current_app_status'] =  each.name,each.current_app_status
 	checkstatus['created_date'] = each.created_date
 	checkstatus['application_status'] = each.get_application_status_display()
 	checkstatus['verification_status'] =each.application_status
 	# pending_application_names.append(checkstatus['applicant_name'])
 	deemed_approved_application_names.append(checkstatus['applicant_name'])
 	deemed_approved_application_dates.append(checkstatus['created_date'])
 	deemed_approved_application_no.append(checkstatus['application_no'])
 
 	# checkstatus['current_status'] =each.application_status
 
 	if each.reason_range_officer != '':
 		checkstatus['remark'] =  each.reason_range_officer
 		checkstatus['remark_date']= each.range_officer_date
 	elif each.reason_depty_ranger_office != '':
 		checkstatus['remark'] =  each.reason_depty_ranger_office
 		checkstatus['remark_date']= each.deputy_officer_date
 	elif each.reason_office != '':
 		checkstatus['remark'] =  each.reason_office
 		checkstatus['remark_date']= each.verify_office_date
 	else:
 		checkstatus['remark'] =  'N/A'
 		checkstatus['remark_date']= 'N/A'
 	if each.application_status == 'R' :
 		checkstatus['remark'] = 'N/A'
 	checkstatus['query'] = ''
 	checkstatus['tp_issue_date'] = each.transit_pass_created_date if each.application_status == 'A' else 'N/A'
 	checkstatus['tp_number'] = each.transit_pass_id
 	# if each.application_status != 'Approved':
 	# 	checkstatus['current_status'] ='Rejected'
 	# tp = TransitPass.objects.filter(app_form__by_user_id=each.id).order_by('-app_form_id')
 	deemed_approved_applicant.append(checkstatus)
 	incr3 = incr3+1
 
 noc_applicant = []
 incr4 = 1
 noc_application_no=[]
 noc_application_names=[]
 noc_application_dates=[]
 for each in noc_list:
 	checkstatus = {}
 	checkstatus['sr'] =incr3
 	checkstatus['applicant_no'] = each.id
 	checkstatus['application_no'] = each.application_no
 	checkstatus['applicant_name'] , checkstatus['current_app_status'] =  each.name,each.current_app_status
 	checkstatus['created_date'] = each.created_date
 	# checkstatus['application_status'] = each.get_application_status_display()
 	checkstatus['verification_status'] =each.application_status
 	# pending_application_names.append(checkstatus['applicant_name'])
 	noc_application_names.append(checkstatus['applicant_name'])
 	noc_application_dates.append(checkstatus['created_date'])
 	noc_application_no.append(checkstatus['application_no'])
 
 	# checkstatus['current_status'] =each.application_status
 
 	checkstatus['query'] = ''
 
 	noc_applicant.append(checkstatus)
 	incr4 = incr4+1
 
 
 # context['pending_applicant'] = pending_applicant
 context['approved_applicant'] = approved_applicant
 context['deemed_approved_applicant'] = deemed_approved_applicant
 context['noc_applicant'] = noc_applicant
 context['pending_application_no'] = set(pending_application_no)
 context['pending_application_names'] = set(pending_application_names)
 context['pending_application_date'] = set(pending_application_dates)
 context['approved_application_no'] = set(approved_application_no)
 context['approved_application_names'] = set(approved_application_names)
 context['approved_application_date'] = set(approved_application_dates)
 context['deemed_approved_application_no'] = set(deemed_approved_application_no)
 context['deemed_approved_application_names'] = set(deemed_approved_application_names)
 context['deemed_approved_application_date'] = set(deemed_approved_application_dates)
 context['noc_application_no'] = set(noc_application_no)
 context['noc_application_names'] = set(noc_application_names)
 context['noc_application_date'] = set(noc_application_dates)
 if groups[0] =='forest range officer':
  urange=ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
  context['no_of_app']=Applicationform.objects.filter(area_range=urange[0].range_name.name).count()
  
  context['no_of_approved'] = Applicationform.objects.filter(application_status='A',area_range=urange[0].range_name.name).count()
  context['no_of_pending'] = Applicationform.objects.filter(application_status='P',area_range=urange[0].range_name.name).count()
  context['no_of_deemed'] = Applicationform.objects.filter(application_status='P',area_range=urange[0].range_name.name,deemed_approval = True).count()
  context['no_of_rejected'] = Applicationform.objects.filter(application_status='R',area_range=urange[0].range_name.name).count()
 elif groups[0] =='deputy range officer':
  context['no_of_app']=Applicationform.objects.filter(d=request.user.id).count()
  context['no_of_approved'] = Applicationform.objects.filter(application_status='A',d=request.user.id).count()
  context['no_of_pending'] = Applicationform.objects.filter(application_status='P',d=request.user.id).count()
  context['no_of_deemed'] = Applicationform.objects.filter(application_status='P',d=request.user.id,deemed_approval = True).count()
  context['no_of_rejected'] = Applicationform.objects.filter(application_status='R',d=request.user.id).count()
 elif groups[0] =='revenue officer':
  rev_range=RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
  context['no_of_app']=Applicationform.objects.filter(area_range=rev_range[0].range_name.name).count()
  context['no_of_approved'] = Applicationform.objects.filter(application_status='A',area_range=rev_range[0].range_name.name).count()
  context['no_of_pending'] = Applicationform.objects.filter(application_status='P',area_range=rev_range[0].range_name.name).count()
  context['no_of_deemed'] = Applicationform.objects.filter(application_status='P',area_range=rev_range[0].range_name.name,deemed_approval = True).count()
  context['no_of_rejected'] = Applicationform.objects.filter(application_status='R',area_range=rev_range[0].range_name.name).count()
 else:
  context['no_of_app']=Applicationform.objects.filter().count()
  context['no_of_approved'] = Applicationform.objects.filter(application_status='A').count()
  context['no_of_pending'] = Applicationform.objects.filter(application_status='P').count()
  context['no_of_deemed'] = Applicationform.objects.filter(application_status='P').count()
  context['no_of_rejected'] = Applicationform.objects.filter(application_status='R').count()
 context['scan_details'], =scan_details ,
 return render(request,"my_app/tigram/officerdash.html",context)
 

@login_required
@group_permissions('pending_applications')
def pending_applications(request):
	context = {}
	groups=request.user.groups.values_list('name',flat = True)

	application = Applicationform.objects.exclude(application_status='A').order_by('-id')
	if application:

		pending_applications = request.POST.get('sel_applicant01')
		filter_applicant = request.POST.get('filter_applicant')
		if pending_applications == 'application_no':
			application = application.filter(application_no__iexact=filter_applicant)
		elif pending_applications == 'application_name':
			application = application.filter(name__iexact=filter_applicant)
		elif pending_applications == 'application_date':
			application = application.filter(created_date=filter_applicant)
		else:
			pass
			# application = application.filter(name__iexact=filter_applicant)

		# application_no
	context['group'] = groups[0]
	if groups[0] =='revenue officer':
		context['text_show'] = 'Revenue Officer'
	elif groups[0] =='deputy range officer':
		context['text_show'] = 'Deputy Range Officer'
		# application = application.filter(verify_office=True)
	elif groups[0] =='forest range officer':
		context['text_show'] = 'Forest Range Officer'
		# application = application.filter(depty_range_officer=True)
	elif groups[0] =='admin':
		context['text_show'] = 'Admin'
	else:
		return HttpResponseRedirect(reverse('index'))
		context['text_show'] = 'Admin'
	context['user'] = request.user
	# context['application']
	applicant = []
	incr = 1
	for each in application:
		checkstatus = {}
		checkstatus['sr'] =incr
		checkstatus['applicant_no'] = each.id
		checkstatus['application_no'] = each.application_no
		checkstatus['applicant_name'] , checkstatus['current_app_status'] =  each.name,each.current_app_status
		checkstatus['created_date'] = each.created_date
		checkstatus['application_status'] = each.get_application_status_display()
		checkstatus['verification_status'] =each.application_status

		# checkstatus['current_status'] =each.application_status

		if each.reason_range_officer != '':
			checkstatus['remark'] =  each.reason_range_officer
			checkstatus['remark_date']= each.range_officer_date
		elif each.reason_depty_ranger_office != '':
			checkstatus['remark'] =  each.reason_depty_ranger_office
			checkstatus['remark_date']= each.deputy_officer_date
		elif each.reason_office != '':
			checkstatus['remark'] =  each.reason_office
			checkstatus['remark_date']= each.verify_office_date
		else:
			checkstatus['remark'] =  'N/A'
			checkstatus['remark_date']= 'N/A'
		checkstatus['query'] = ''
		checkstatus['tp_issue_date'] = each.transit_pass_created_date if each.application_status == 'A' else 'N/A'
		checkstatus['tp_number'] = each.transit_pass_id
		# if each.application_status != 'Approved':
		# 	checkstatus['current_status'] ='Rejected'
		# tp = TransitPass.objects.filter(app_form__by_user_id=each.id).order_by('-app_form_id')
		applicant.append(checkstatus)
		incr = incr+1
	context['application'] = applicant
		# application.save()
	return JsonResponse({'response_code':'success','application':context['application']})

@login_required
def approved_applications(request):
	context = {}
	groups=request.user.groups.values_list('name',flat = True)
	application = Applicationform.objects.filter(application_status='A').order_by('-id')
	if application:

		approved_applications = request.POST.get('sel_applicant01')
		filter_applicant = request.POST.get('filter_applicant')
		if approved_applications == 'application_no':
			application = application.filter(application_no__iexact=filter_applicant)
		elif approved_applications == 'application_name':
			application = application.filter(name__iexact=filter_applicant)
		elif approved_applications == 'application_date':
			application = application.filter(created_date=filter_applicant)
		else:
			pass
	context['group'] = groups[0]
	if groups[0] =='revenue officer':
		context['text_show'] = 'Revenue Officer'
	elif groups[0] =='deputy range officer':
		context['text_show'] = 'Deputy Range Officer'
		# application = application.filter(verify_office=True)
	elif groups[0] =='forest range officer':
		context['text_show'] = 'Forest Range Officer'
		# application = application.filter(depty_range_officer=True)
	elif groups[0] =='admin':
		context['text_show'] = 'Admin'
	else:
		return HttpResponseRedirect(reverse('index'))
		context['text_show'] = 'Admin'
	context['user'] = request.user
	# context['application']
	applicant = []
	incr = 1
	for each in application:
		checkstatus = {}
		checkstatus['sr'] =incr
		checkstatus['applicant_no'] = each.id
		checkstatus['application_no'] = each.application_no
		checkstatus['applicant_name'] , checkstatus['current_app_status'] =  each.name,each.current_app_status
		checkstatus['created_date'] = each.created_date
		checkstatus['application_status'] = each.get_application_status_display()
		checkstatus['verification_status'] =each.application_status

		# checkstatus['current_status'] =each.application_status

		if each.reason_range_officer != '':
			checkstatus['remark'] =  each.reason_range_officer
			checkstatus['remark_date']= each.range_officer_date
		elif each.reason_depty_ranger_office != '':
			checkstatus['remark'] =  each.reason_depty_ranger_office
			checkstatus['remark_date']= each.deputy_officer_date
		elif each.reason_office != '':
			checkstatus['remark'] =  each.reason_office
			checkstatus['remark_date']= each.verify_office_date
		else:
			checkstatus['remark'] =  'N/A'
			checkstatus['remark_date']= 'N/A'
		checkstatus['query'] = ''
		checkstatus['tp_issue_date'] = each.transit_pass_created_date if each.application_status == 'A' else 'N/A'
		checkstatus['tp_number'] = each.transit_pass_id
		# if each.application_status != 'Approved':
		# 	checkstatus['current_status'] ='Rejected'
		# tp = TransitPass.objects.filter(app_form__by_user_id=each.id).order_by('-app_form_id')
		applicant.append(checkstatus)
		incr = incr+1
	context['application'] = applicant
		# application.save()
	return JsonResponse({'response_code':'success','application':context['application']})
@login_required

@group_permissions('user_dashboard')
def dashboard(request):
	context = {}
	groups=request.user.groups.values_list('name',flat = True)
	context['groups'] = groups
	context['user'] = request.user
	context['current_page']='dashboard'
	return render(request,"my_app/tigram/dashboard.html",context)


@login_required
def select_village(request):
 if request.method == 'POST':
  if request.POST['cutting']=="Cutting Permission":
   selected_village = request.POST['village']
   context = {} 
   v = Village.objects.get(village_name=selected_village)
   context['village_name'] = v.village_name
   context['village_taluka'] = v.taluka.taluka_name
   t = Taluka.objects.get(taluka_name=context['village_taluka'])
   context['village_dist'] = t.dist.district_name
   context['tempLinkage'] = TempLinkage.objects.filter(village=v.village_name)
   context['proof_list'] = PhotoProof.objects.all().order_by('name').values('name')
   context['trees_species'] = TreeSpecies.objects.filter(is_noc=False,is_delete=False).values('name')
   groups=request.user.groups.values_list('name',flat = True)
   context['groups'] = groups
   village = Village.objects.get(village_name=selected_village) 
   try:
    if request.POST['coffee'] == "No":
     if village.is_notified:
      context['allspecies'] = AllSpecies.objects.all().order_by('name').values('name')
      return render(request,"my_app/tigram/notified_form_new.html", context=context)
     else:
      return render(request,"my_app/tigram/form3.html",context=context)
    else:
      context['allspecies'] = AllSpecies.objects.all().order_by('name').values('name')
      return render(request,"my_app/tigram/notified_form_new.html", context=context)
   except:
     messages.error(request,"Select land info question")
  if request.POST['cutting']=="Transit Pass":
    try:
     context = {}
     context['data']  = Applicationform.objects.get(application_no=request.POST['transit_num'])
     context['apor'] = ApprovedTimberLog.objects.filter(appform_id= context['data'].id , is_approved = True, is_applied = False)
     context['log'] = ApprovedTimberLog.objects.filter(appform_id= context['data'].id , is_approved = True, is_applied = False)
     context['img'] = image_documents.objects.get(app_form= context['data'].id) 
     context['media_prefix'] = settings.MEDIA_PREFIX
     if context['data'].application_status== "A":
      return render(request,"my_app/tigram/form3_transit.html",context=context) 
     else :
         messages.error(request,"Cutting pass not yet approved") 
         return redirect('dashboard')
    except:
        messages.error(request,"Cutting pass does not exist") 
        return redirect('dashboard')       
 villages = Village.objects.all()
 notified_villages = [village.village_name for village in villages if village.is_notified]
 notified_villages_json = json.dumps(notified_villages)

 return render(request, "my_app/tigram/select_village.html", {'villages': villages, 'notified_villages_json': notified_villages_json})










@login_required
def user_logout(request):
 if request.user!='':
  session_keys = list(request.session.keys())
  for key in session_keys:
   del request.session[key]
  logout(request)
  return HttpResponseRedirect(reverse('index'))
 return redirect('index')

@login_required
def admin_logout(request):
 if request.user!='':
  session_keys = list(request.session.keys())
  for key in session_keys:
   del request.session[key]
  logout(request)
  return HttpResponseRedirect(reverse('admin_login'))
 return redirect('admin_login')






def generate_app_id(uid,app_id): #uid
	# uid=31254
	# date = datetime.date.today()
	date1 = date.today()
	# gno = '0'*(4-len(str(uid)))
	# uid = str(gno)+str(uid)
	applicant_no = 'TG/'+str(date1.year)+'/'+str(date1.month)+'/'+str(uid)+'/'+str(app_id)
	# date1 = datetime.date.today()
	applicant_no = applicant_no.replace('-','')
	return applicant_no

def generate_noc_app_id(uid,app_id): #uid
	# uid=31254
	# date = datetime.date.today()
	date1 = date.today()
	# gno = '0'*(4-len(str(uid)))
	# uid = str(gno)+str(uid)
	applicant_no = 'NOC/'+str(date1.year)+'/'+str(date1.month)+'/'+str(uid)+'/'+str(app_id)
	# date1 = datetime.date.today()
	applicant_no = applicant_no.replace('-','')
	return applicant_no


def generate_user_id(uid): #uid
	# uid=31254
	date1 = date.today()
	gno = '0'*(4-len(str(uid)))
	uid = str(gno)+str(uid)
	user_id = str(date1)+uid
	user_id = user_id.replace('-','')
	return user_id
def post_to_url(url, data):
    fields = ''
    for key, value in data.items():
        fields += key + '=' + value + '&'
    fields = fields[:-1] # remove the trailing '&'

    response = requests.post(url, data=fields)
    result = response.text

    errors = response.raise_for_status()

    response_code = response.status_code

    return result


@never_cache
def signup(request):
	context = {}
	# if request.method =='GET':
	if not request.is_ajax():
		context['proof_list'] = PhotoProof.objects.all().values()
	context['response_code']=''
	if request.method =='POST':
		username = request.POST.get('uname')
		email = request.POST.get('email')
		phone = request.POST.get('number')
		passwd = request.POST.get('psw')
		passwd2 = request.POST.get('psw2')
		address = request.POST.get('address')
		photo_proof_no = request.POST.get('photo_proof_no')
		photo_proof_name = request.POST.get('photo_proof_select')
		photo_proof_doc = request.FILES.get('photo_proof')
		random_number = random.randint(100000, 999999)
		rand_no = str(random_number)
		if '@' not in email or '.' not in email :
			context['response_code'] = 'error'
			context['message'] = 'Invalid Email Id'
		if passwd2!=passwd :
			context['response_code'] = 'error'
			context['message'] = 'Password and Confirm Password Must Match!'
		if context['response_code'] != '':
			if request.is_ajax():
				return JsonResponse(context)
			return render(request,"my_app/tigram/registration.html",context)
		try :
			email=email.lower().strip()
			phone=phone.strip()
			username=username.strip()
			address = address.strip()
			passwd = passwd.strip()
			if CustomUser.objects.filter(Q(email=email)|Q(phone=phone)).exists():
				context['response_code'] = 'error'
				context['message'] = 'User already exists if not wait 5 mins !'
				if request.is_ajax():
					return JsonResponse(context)
				return render(request,"my_app/tigram/registration.html",context)
			proof_type = PhotoProof.objects.filter(name__iexact=photo_proof_name)


			user_create = CustomUser.objects.create_user(email,passwd,
				name=username,phone=phone,address=address,
				photo_proof_no=photo_proof_no,photo_proof_name=photo_proof_name,
				photo_proof_type_id=proof_type[0].id,
				)
			generated_id = generate_user_id(user_create.id)
			user_create.user_id = generated_id
			make_id = str(user_create.id)+'r'
			url = '/static/media/upload/'
			saved_photo=upload_product_image_file(make_id,photo_proof_doc,url,'PhotoProof')
			user_create.photo_proof_img = saved_photo
			# UserId:Date01
			# user_create.user_id=
			user_create.save()
			group = Group.objects.get(name='user')
			user_create.groups.add(group)
			context['message']= 'Verify OTP! '
			context['response_code'] ='success'
			if request.is_ajax():
				# context['proof_list']=list(context['proof_list'])
				return JsonResponse(context)
			# login(request,user_create)
			return render(request,'my_app/tigram/register_otp.html',{"phone":phone})
			# return HttpResponseRedirect(reverse('user_login'))
		except Exception as Error:
			context['message']= 'User has not been created! '
			context['response_code'] ='error'
			if request.is_ajax():
				# context['proof_list']=list(context['proof_list'])
				return JsonResponse(context)
			return render(request,"my_app/tigram/registration.html",context)
	return render(request,"my_app/tigram/registration.html",context)



def create_new_user(request,group_name):
	context={}
	if request.method =='POST':
		username = request.POST.get('uname')
		email = request.POST.get('email')
		phone = request.POST.get('number')
		passwd = request.POST.get('psw')
		passwd2 = request.POST.get('psw2')
		address = request.POST.get('address')
		photo_proof_no = request.POST.get('photo_proof_no')
		photo_proof_name = request.POST.get('photo_proof_select')
		photo_proof_doc = request.FILES.get('photo_proof')
		if '@' not in email or '.' not in email :
			context['response_code'] = 'error'
			context['message'] = 'Invalid Email Id'
		if passwd2!=passwd :
			context['response_code'] = 'error'
			context['message'] = 'Password and Confirm Password Must Match!'

		if 'response_code' in context:
			return False,context
			# return JsonResponse(context)
			# return render(request,"my_app/tigram/registration.html",context)
		try :
			email=email.lower().strip()
			phone=phone.strip()
			username=username.strip()
			address = address.strip()
			passwd = passwd.strip()
			if CustomUser.objects.filter(Q(email=email)|Q(phone=phone)).exists():
				context['response_code'] = 'error'
				context['message'] = 'User already exists!'
				return False,context
				# return JsonResponse(context)
				# return render(request,"my_app/tigram/registration.html",context)
			proof_type = PhotoProof.objects.filter(name__iexact=photo_proof_name)
			user_create = CustomUser.objects.create_user(email,passwd,
				name=username,phone=phone,address=address,
				photo_proof_no=photo_proof_no,photo_proof_name=photo_proof_name,
				photo_proof_type_id=proof_type[0].id
				)
			generated_id = generate_user_id(user_create.id)
			user_create.user_id = generated_id
			make_id = str(user_create.id)+'r'
			url = '/static/media/upload/'
			saved_photo=upload_product_image_file(make_id,photo_proof_doc,url,'PhotoProof')
			user_create.photo_proof_img = saved_photo
			# UserId:Date01
			# user_create.user_id=
			user_create.save()
			group = Group.objects.get(name=group_name)
			user_create.groups.add(group)
			context['message']= 'User created successfully! '
			context['response_code'] ='success'
			return user_create,context
		except Exception as error:
			context['message']= 'User not created.Please check data entered!'
			context['response_code'] ='error'
			return True,context

	else:
		return True,context
	return True,context

@login_required
@group_permissions('application_form')
@never_cache
def application_form(request):
 context = {}
 if request.method == "POST":
  name=request.POST.get('uname')
  address=request.POST.get('add')
  id_card_number = request.POST.get('id_number')
  id_type = request.POST.get('photo_proof_select')
  survey_no=request.POST.get('sno')
  tree_proposed=request.POST.get('treep')
  tree=tree_proposed
 
  village=request.POST.get('village')
  district=request.POST.get('dist')
  block=request.POST.get('block')
  taluka=request.POST.get('taluka')
  division=request.POST.get('division')
  area_range=request.POST.get('area_range')
  pincode=request.POST.get('pincode')
 
  ownership_proof_img=request.FILES.get('ownership_proof_img')
  revenue_application_img=request.FILES.get('revenue_application_img')
  revenue_approval_img=request.FILES.get('revenue_approval_img')
  declaration_img=request.FILES.get('declaration_img')
  location_sketch_img=request.FILES.get('location_sketch_img')
  tree_ownership_img=request.FILES.get('tree_ownership_img')
  aadhar_card_img=request.FILES.get('aadhar_card_img')

  lic_img=request.FILES.get('lic_img')
  tree_species=request.POST.get('tree_species')
  purpose = request.POST.get('purpose_cut')
  veh_reg=request.POST.get('veh_reg')
  driver_name= request.POST.get('driver_name')
  phone = request.POST.get('phn')
  mode = request.POST.get('mode')
  species = request.POST.getlist('species[]')
  length = request.POST.getlist('length[]')
  breadth = request.POST.getlist('breadth[]')
  volume = request.POST.getlist('volume[]')
  
  is_vehicle = request.POST.get('option')
  is_cut = request.POST.get('trees_cut')
  destination_state = request.POST.get('dest_state')
  if check_sanitization(name,address,id_card_number,id_type,survey_no,village,district,block,taluka,division,area_range,pincode,destination_state):
   pass
  else:
    messages.error(request,"Only speacial chars '-' '/' '.' ',' '@' allowed")
    return redirect('dashboard')
  tlog=[]
 try: 
  rangedetails = Range.objects.get(name=area_range)
  revenue=RevenueOfficerdetail.objects.filter(range_name=rangedetails)
  for r in revenue:
      try:
       u = CustomUser.objects.get(id = r.Rev_user.id,is_delete= False)
       revenueid = u.id
      
      except:
       pass
      
  
  
 except:
    messages.error(request,"Revenue Officer not yet assigned !")	
 
 url='static/media/'
 try:
  application = Applicationform.objects.create(
			name=name,address=address,destination_details='',
			survey_no=survey_no,village=village,total_trees=tree_proposed,
			district=district,species_of_trees=tree_species,pincode=pincode,
			purpose=purpose,block=block,taluka=taluka,division=division,destination_state=destination_state,id_card_number=id_card_number,
			area_range=area_range,by_user=request.user,id_type=id_type
			)

  saved_image=upload_product_image_file(application.id,aadhar_card_img,url,'AadharCard')

  saved_image_2=upload_product_image_file(application.id,revenue_approval_img,url,'RevenueApproval')
  saved_image_1=upload_product_image_file(application.id,declaration_img,url,'Declaration')
  saved_image_3=upload_product_image_file(application.id,revenue_application_img,url,'RevenueApplication')
  saved_image_4=upload_product_image_file(application.id,location_sketch_img,url,'LocationSketch')
  saved_image_5=upload_product_image_file(application.id,tree_ownership_img,url,'TreeOwnership')
  saved_image_6=upload_product_image_file(application.id,ownership_proof_img,url,'ProofOfOwnership')

  application.proof_of_ownership_of_tree=saved_image_6
  image_doc=image_documents.objects.create(app_form=application,
revenue_approval=saved_image_2,declaration=saved_image_1,
revenue_application=saved_image_3,location_sktech=saved_image_4,
tree_ownership_detail=saved_image_5,aadhar_detail=saved_image,

)
  image_doc.save()
  uid=request.user.id
  application.application_no=generate_app_id(uid,application.id)
  application.signature_img = True
  application.revenue_application = True
  application.location_sktech = True
  application.tree_ownership_detail = True
  application.aadhar_detail = True
  application.assgn_deputy = 'assgned'
  application.verify_office=True
  application.application_status='L'
  application.reason_office='Recommended'
  application.approved_by_revenue_id = revenueid
  if destination_state != 'Kerala':
    application.other_state = True
  if is_cut =='yes' :
    application.trees_cutted= True
  else:
    application.trees_cutted= False

  if len(species) >0:
    for i in range(len(species)):
     timber = Timberlogdetails(appform=application,species_of_tree=species[i],
length=length[i],breadth=breadth[i],volume=volume[i])
     timber.save()
    application.save()

  context['transit_succ'] = 'true'
  messages.error(request,"Application has submitted.Please upload location details through mobile application.")
  return redirect('dashboard')
 except Exception as err:
   messages.add_message(request, messages.ERROR, 'Application has not submitted!')
   timber = Timberlogdetails.objects.filter(appform=application)
   timber.delete()
   application.delete()
   image_doc.delete()
   return redirect('dashboard')
 return render(request,"my_app/tigram/form3.html",context=context)


























































































































































































































































































































































@login_required
@never_cache


def notified_application_form(request):


















 
 context={}
 groups=request.user.groups.values_list('name',flat = True)
 context['groups'] = groups
 if request.method == "POST":
  name=request.POST.get('uname')
  address=request.POST.get('add')
  id_card_number = request.POST.get('id_number')
  id_nu = request.POST.get('id_number')
  id_ty = request.POST["photo_proof_select"]
  if id_ty == "":
    messages.error(request,"Id proof not selected")
    return render(request,"my_app/tigram/form3.html",context=context)
  else:
   id_ty = request.POST["photo_proof_select"]
  survey_no=request.POST.get('sno')
  tree_proposed=request.POST.get('treep')
  village=request.POST.get('village')
  district=request.POST.get('dist')
  block=request.POST.get('block')
  taluka=request.POST.get('taluka')
  division=request.POST.get('division')
  area_range=request.POST.get('area_range')
  pincode=request.POST.get('pincode')
  ownership_proof_img=request.FILES.get('ownership_proof_img')
  revenue_application_img=request.FILES.get('revenue_application_img')
  revenue_approval_img=request.FILES.get('revenue_approval_img')
  declaration_img=request.FILES.get('declaration_img')
  location_sketch_img=request.FILES.get('location_sketch_img')
  tree_ownership_img=request.FILES.get('tree_ownership_img')
  aadhar_card_img=request.FILES.get('aadhar_card_img')
  
  lic_img=request.FILES.get('lic_img')
  
  allspecies=request.POST.get('allspecies')   
  land_extent = request.POST.get('land_extent')
  purpose = request.POST.get('purpose_cut')
  veh_reg=request.POST.get('veh_reg')
  driver_name= request.POST.get('driver_name')
  phone = request.POST.get('phn')
  mode = request.POST.get('mode')
  is_cut = request.POST.get('trees_cut')
  check_list = request.POST.getlist('data')
  
  # if is_cut == 'yes':
  # 	species = request.POST.getlist('species[]')
  # 	length = request.POST.getlist('length[]')
  # 	breadth = request.POST.getlist('breadth[]')
  # 	volume = request.POST.getlist('volume[]')
  # 	latitude = request.POST.getlist('latitude[]')
  # 	longitude = request.POST.getlist('longitude[]')
  # else:
  	# species = request.POST.getlist('species02[]')
  	# latitude = request.POST.getlist('latitude02[]')
  	# longitude = request.POST.getlist('longitude02[]')
  # species = request.POST.getlist('species02[]')
  # latitude = request.POST.getlist('latitude02[]')
  # longitude = request.POST.getlist('longitude02[]')
  species = request.POST.getlist('species[]')
  t = ""
  for i in species:
	  t = t + ","  + i
  tree_species= t[1:]
  length = request.POST.getlist('length[]')
  breadth = request.POST.getlist('breadth[]')
  volume = request.POST.getlist('volume[]')
  latitude = request.POST.getlist('latitude[]')
  longitude = request.POST.getlist('longitude[]')
  
  # return JsonResponse({'message':'hii'})
  is_vehicle = request.POST.get('option')
  is_log = request.POST.get('log_option')
  destination_state = request.POST.get('dest_state')
  # treep = request.POST.get('treep')
  destination_address = request.POST.get('destination_details')
  # Timberlogdetails.objects.create()
  tlog=[]
  #revenueID
  if check_sanitization(name,address,id_card_number,survey_no,village,district,block,taluka,division,area_range,pincode,destination_state):
   pass
  else:
    messages.error(request,"Only speacial chars '-' '/' '.' ',' '@' allowed")
    return redirect("dashboard")
  try: 
   rangedetails = Range.objects.get(name=area_range)
   revenue=RevenueOfficerdetail.objects.filter(range_name=rangedetails)
   for r in revenue:
     try:
      u = CustomUser.objects.get(id = r.Rev_user.id,is_delete= False)
      revenueid = u.id
     except:
      pass
      
  
  
  except:
    messages.error(request,"Revenue Officer not yet assigned !")
  
  # revenuedate=datetime.date.today
  #done
  
  
  #ggg
  # url = settings.MEDIA_URL+'upload/aadhar_card/'
  
  url='static/media/'
  try:
   tree_proposed=len(species)
   # Determine species_of_trees based on land_extent

   species_of_trees = tree_species  # Species selected from the TreeSpecies table



     # Default value
   application = Applicationform.objects.create(
   	name=name,address=address,
   	survey_no=survey_no,village=village,total_trees=tree_proposed,
   	district=district,species_of_trees=species_of_trees,pincode=pincode,
   	purpose=purpose,block=block,taluka=taluka,division=division,destination_details='',destination_state='',
   	area_range=area_range,by_user=request.user,id_card_number=id_nu,id_type=id_ty,
   	)
   saved_image=upload_product_image_file(application.id,aadhar_card_img,url,'AadharCard')
   saved_image_2=upload_product_image_file(application.id,revenue_approval_img,url,'RevenueApproval')
   saved_image_1=upload_product_image_file(application.id,declaration_img,url,'Declaration')
   saved_image_3=upload_product_image_file(application.id,revenue_application_img,url,'RevenueApplication')
   saved_image_4=upload_product_image_file(application.id,location_sketch_img,url,'LocationSketch')
   saved_image_5=upload_product_image_file(application.id,tree_ownership_img,url,'TreeOwnership')
   saved_image_6=upload_product_image_file(application.id,ownership_proof_img,url,'ProofOfOwnership')
   
   application.proof_of_ownership_of_tree=saved_image_6
   
   image_doc=image_documents.objects.create(app_form=application,
   		revenue_approval=saved_image_2,declaration=saved_image_1,
   		revenue_application=saved_image_3,location_sktech=saved_image_4,
   		tree_ownership_detail=saved_image_5,aadhar_detail=saved_image,
   		
   	)
   # application.revenue_approval = True
   # application.declaration = True
   uid=request.user.id
   application.application_no=generate_app_id(uid,application.id)
   application.signature_img = True
   application.revenue_application = True
   application.location_sktech = True
   application.tree_ownership_detail = True
   application.aadhar_detail = True
   application.is_form_two =True
   #revenue autoapproval start
   application.verify_office=True
   application.application_status='L'
   application.reason_office='Recommended'
   application.approved_by_revenue_id = revenueid
   # application.verify_office_date=revenuedate
   #revenue autoapproval end
   if destination_state != 'Kerala':
    application.other_state = True
   if is_cut =='yes' :
    application.trees_cutted= True
   else:
   	application.trees_cutted= False
   # if is_log == 'yes':
   # 	if len(species) >0 :
   # 		for i in range(len(species)):
   # 			timber = Timberlogdetails(appform=application,species_of_tree=species[i],
   # 			length=length[i],volume=volume[i],breadth=breadth[i],latitude=latitude[i],longitude=longitude[i])
   # 			tlog.append(timber)
   # 		Timberlogdetails.objects.bulk_create(tlog)
   if len(species) >0 :
    for i in range(len(species)):
       timber = Timberlogdetails(appform=application,species_of_tree=species[i],length=length[i],breadth=breadth[i],volume=volume[i])
       timber.save()
    
   application.save()
   messages.add_message(request, messages.SUCCESS, 'Application Submitted Successfully, Please upload location from mobile application !')
   context['transit_succ'] = 'true'
   return redirect("dashboard")
  except Exception as err:
   messages.add_message(request, messages.ERROR, 'Application has not submitted!')
   timber = Timberlogdetails.objects.filter(appform=application)
   timber.delete()
   application.delete()
   image_doc.delete()
   return redirect("dashboard")
 return render(request,"my_app/tigram/notified_form_new.html", context)

@login_required


@never_cache
def noc_application_form(request):
	context={}
	context['proof_list'] = PhotoProof.objects.all().order_by('name').values()
	context['trees_species'] = TreeSpecies.objects.filter(is_noc=True,is_delete=False).order_by('name').values('name')
	context['range_areas'] = Range.objects.filter(is_delete=False).order_by('name').values('name')
	context['district_name'] = District.objects.all().order_by('district_name').values('district_name')

	context['division_areas'] = Division.objects.filter(is_delete=False).order_by('name').values('name')
	groups=request.user.groups.values_list('name',flat = True)
	context['groups'] = groups
	if request.method == "POST":
		name=request.POST.get('uname')
		address=request.POST.get('add')
		survey_no=request.POST.get('sno')
		tree_proposed=request.POST.get('treep')
		village=request.POST.get('village')
		district=request.POST.get('dist')
		block=request.POST.get('block')
		taluka=request.POST.get('taluka')
		division=request.POST.get('division')
		area_range=request.POST.get('area_range')
		pincode=request.POST.get('pincode')
		aadhar_card_img=request.FILES.get('aadhar_card_img')
		signature_img = request.FILES.get('signature_img')
		# lic_img=request.FILES.get('lic_img')
		tree_species=request.POST.get('tree_species')
		purpose = request.POST.get('purpose_cut')
		veh_reg=request.POST.get('veh_reg')
		driver_name= request.POST.get('driver_name')
		phone = request.POST.get('phn')
		mode = request.POST.get('mode')
		species = request.POST.getlist('species[]')
		length = request.POST.getlist('length[]')
		breadth = request.POST.getlist('breadth[]')
		volume = request.POST.getlist('volume[]')
		is_vehicle = request.POST.get('option')
		is_log = request.POST.get('log_option')
		is_cut = request.POST.get('trees_cut')
		# treep = request.POST.get('treep')
		destination_address = request.POST.get('destination_details')
		# Timberlogdetails.objects.create()
		tlog=[]

		try:
			application = Applicationform.objects.create(
				name=name,address=address,destination_details=destination_address,
				survey_no=survey_no,village=village,total_trees=tree_proposed,
				district=district,species_of_trees=tree_species,pincode=pincode,
				purpose=purpose,block=block,taluka=taluka,division=division,
				area_range=area_range,by_user=request.user,is_noc=True,destination_state="")
			saved_image=upload_product_image_file(application,aadhar_card_img,url,'AadharCard')
			# saved_image_2=upload_product_image_file(application.id,revenue_approval_img,url,'RevenueApproval')
			# saved_image_1=upload_product_image_file(application.id,declaration_img,url,'Declaration')
			# saved_image_3=upload_product_image_file(application.id,revenue_application_img,url,'RevenueApplication')
			# saved_image_4=upload_product_image_file(application.id,location_sketch_img,url,'LocationSketch')
			# saved_image_5=upload_product_image_file(application.id,tree_ownership_img,url,'TreeOwnership')
			# saved_image_6=upload_product_image_file(application.id,ownership_proof_img,url,'ProofOfOwnership')
			# application.proof_of_ownership_of_tree=saved_image_6


			image_doc=image_documents.objects.create(app_form=application[0],
					# revenue_approval=saved_image_2,declaration=saved_image_1,
					# revenue_approval='no_image',
					# revenue_application=saved_image_3,location_sktech=saved_image_4,
					# tree_ownership_detail=saved_image_5,
					aadhar_detail=saved_image,
					signature_img=saved_image_8)
			# application.revenue_approval = True
			# application.declaration = True
			uid=request.user.id
			application[0].application_no=generate_noc_app_id(uid,application[0].id)
			application[0].signature_img = True
			# application.revenue_application = True
			# application.location_sktech = True
			# application.tree_ownership_detail = True
			application[0].aadhar_detail = True
			if is_cut =='yes' :
				application[0].trees_cutted= True
			else:
				application[0].trees_cutted= False
			if is_log == 'yes':
				if len(species) >0 :
					for i in range(len(species)):
						timber = Timberlogdetails(appform=application[0],species_of_tree=species[i],
						length=length[i],volume=volume[i],breadth=breadth[i])
						tlog.append(timber)
					Timberlogdetails.objects.bulk_create(tlog)
            
			qr_code=get_qr_code(application[0].id)
			qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, application[0].id)
			application_detail = Applicationform.objects.filter(id=application[0].id)
			if is_vehicle == 'yes':
				# saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')
				vehicle = Vehicle_detials.objects.create(app_form=application[0],
					# license_image=saved_image_7,
					vehicle_reg_no=veh_reg,
					driver_name=driver_name,driver_phone=phone,
					mode_of_transport=mode
					)

				transit_pass=TransitPass.objects.create(
						vehicle_reg_no=veh_reg,
						driver_name =driver_name,
						driver_phone = phone,
						mode_of_transport = mode,
						state = application_detail[0].state,
						district = application_detail[0].district,
						taluka = application_detail[0].taluka,
						block = application_detail[0].block,
						village = application_detail[0].village,
						qr_code = qr_code,
						qr_code_img =qr_img,
						app_form_id = application[0].id
					)
			else:
					transit_pass=TransitPass.objects.create(
						state = application_detail[0].state,
						district = application_detail[0].district,
						taluka = application_detail[0].taluka,
						block = application_detail[0].block,
						village = application_detail[0].village,
						qr_code = qr_code,
						qr_code_img =qr_img,
						app_form_id = application[0].id
					)
			application_detail.update(
					# reason_range_officer = reason ,
					application_status = 'A',
					# approved_by = request.user,
					# verify_range_officer = True,
					# range_officer_date = date.today(),
					transit_pass_id=transit_pass.id,
					transit_pass_created_date = date.today(),
					)
			context['transit_succ'] = 'true'
			messages.add_message(request, messages.SUCCESS, 'Application Submitted Successfully!')
			return redirect('dashboard')
		except Exception as err:
			messages.add_message(request, messages.ERROR, 'Application has not submitted!'),application.delete(),image_doc.delete()
			return redirect('dashboard')


		# return HttpResponseRedirect(reverse('dashboard'))
	# return render(request,"my_app/tigram/form2.html",context)
	return render(request,"my_app/tigram/noc_form.html",context)

@login_required
@group_required('revenue officer','deputy range officer','forest range officer')

def application_list(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	context['group'] = groups
	applications = Applicationform.objects.all()
	paginator = Paginator(applications, 3)
	# paginator = Paginator(applications, 3)
	page = 3
	try:
		applications_list = paginator.page(page)
	except PageNotAnInteger:
		applications_list = paginator.page(1)
	except EmptyPage:
		applications_list = paginator.page(paginator.num_pages)

	return render(request,"my_app/tigram/application_list.html",{'applications':applications_list})

APPLICATION={
	'name': 'NAME',
	'address' : 'ADDRESS'
}

@login_required

@group_permissions('update_vehicle')
def update_vehicle(request,app_id):
	groups=request.user.groups.values_list('name',flat = True)
	application_detail = Applicationform.objects.filter(id=app_id)
	if not application_detail:
		message = "Not Updated!"
		return JsonResponse(
		{'message':message,'status':'200'})
	# license_image=
	veh_reg=request.POST.get('veh_reg')
	driver_name= request.POST.get('driver_name')
	phone = request.POST.get('phn')
	mode = request.POST.get('mode')
	lic_img=request.FILES.get('lic_img',None)
	vehicle = Vehicle_detials.objects.filter(app_form_id=app_id)
	message=''
	# request.POST.get('vehicle_detail')
	url=''
	license_image=''
	if vehicle:
		if lic_img is None:
			# license_image=request.POST.get('lic_img_val')
			vehicle = vehicle.update(
					vehicle_reg_no=veh_reg,
					driver_name=driver_name,driver_phone=phone,
					mode_of_transport=mode
					)
			message='Vehicles details updated successfully!'
		else:
			license_image=upload_product_image_file(app_id,lic_img,url,'License')
			vehicle = vehicle.update(
					vehicle_reg_no=veh_reg,	license_image=license_image,
					driver_name=driver_name,driver_phone=phone,
					mode_of_transport=mode
					)
			message='Vehicles details updated successfully!'
		# vehicle=vehicle[0]

	# timber_log = Timberlogdetails.objects.filter(appform_id=app_id).values()
	else:
			license_image=upload_product_image_file(app_id,lic_img,url,'License')
	# if is_vehicle == 'yes':
			vehicle = Vehicle_detials.objects.create(app_form_id=app_id,
				vehicle_reg_no=veh_reg, license_image=license_image,
				driver_name=driver_name,driver_phone=phone,
				mode_of_transport=mode
				)
			message='Vehicles details added successfully!'
	# transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
	return JsonResponse(
		{'vehicle':vehicle,'message':message,'pic_url':license_image,'status':'200'})
	# return render(request,"my_app/tigram/userviewapplication.html",
	# 	{'vehicle':vehicle,'trees_species_list':trees_species_list})

@group_permissions('update_vehicle')
def update_saved_documents(request,app_id):
	groups=request.user.groups.values_list('name',flat = True)
	application_detail = Applicationform.objects.filter(id=app_id)
	document = image_documents.objects.filter(app_form_id=app_id)
	if not application_detail:

		message = "Not Updated!"
		return JsonResponse(
		{'message':message,'status':'200'})
	ownership_proof_img=request.FILES.get('ownership_proof_img',None)
	revenue_application = request.FILES.get('revenue_application', None)
	revenue_approval = request.FILES.get('revenue_approval', None)
	declaration = request.FILES.get('declaration', None)
	location_sktech = request.FILES.get('location_sktech', None)
	tree_ownership_detail = request.FILES.get('tree_ownership_detail', None)
	aadhar_detail = request.FILES.get('aadhar_detail', None)
	# document = image_documents.objects.filter(app_form_id=app_id)
	url = ''
	doc_image = ''
	message = ''
	if application_detail:

		if ownership_proof_img is None:

			# ownership_proof_img1 = upload_product_image_file(app_id, ownership_proof_img, url, 'ProofOfOwnership')
			application_detail = application_detail.update(
				# vehicle_reg_no=veh_reg,
				# driver_name=driver_name,driver_phone=phone,
				# mode_of_transport=mode
				proof_of_ownership_of_tree=ownership_proof_img
			)
			message = 'image details updated successfully!'
		else:

			ownership_proof_img=upload_product_image_file(app_id,ownership_proof_img,url,'ProofOfOwnership')
			application_detail = application_detail.update(
				proof_of_ownership_of_tree=ownership_proof_img
					)
			message=' details updated successfully!'
	else:

		ownership_proof_img=upload_product_image_file(app_id,ownership_proof_img,url,'Proof_of_ownership')

		application_detail = application_detail.update(
			proof_of_ownership_of_tree=ownership_proof_img
		)
		message = ' details updated successfully!'

	if document:
		revenue_application = upload_product_image_file(app_id, revenue_application, url, 'RevenueApplication')
		revenue_approval = upload_product_image_file(app_id, revenue_approval, url, 'RevenueApproval')
		declaration = upload_product_image_file(app_id, declaration, url, 'Declaration')
		location_sktech = upload_product_image_file(app_id, location_sktech, url, 'LocationSketch')
		tree_ownership_detail = upload_product_image_file(app_id, tree_ownership_detail, url, 'TreeOwnership')
		aadhar_detail = upload_product_image_file(app_id, aadhar_detail, url, 'AadharCard')
		document = document.update(revenue_application=revenue_application,revenue_approval=revenue_approval,declaration=declaration,location_sktech=location_sktech,tree_ownership_detail=tree_ownership_detail,aadhar_detail=aadhar_detail
			)
		message = 'image details updated successfully!'

	return JsonResponse(
		{'ownership_proof_img':ownership_proof_img,'revenue_application':revenue_application,'revenue_approval':revenue_approval,'declaration':declaration,'location_sktech':location_sktech,'tree_ownership_detail':tree_ownership_detail,'aadhar_detail':aadhar_detail,'message':message,'pic_url':ownership_proof_img,'pic1_url':revenue_application,'pic2_url':revenue_approval,'pic3_url':declaration,'pic4_url':location_sktech,'pic5_url':tree_ownership_detail,'pic6_url':aadhar_detail,'status':'200'})



	# timber_log = Timberlogdetails.objects.filter(appform_id=app_id).values()

	# return render(request,"my_app/tigram/userviewapplication.html",
	# 	{'vehicle':vehicle,'trees_species_list':trees_species_list})
@login_required

@group_permissions('application_view')
@never_cache
def application_view(request,app_id):
 groups=request.user.groups.values_list('name',flat = True)
 if groups[0] == "user":
     return HttpResponse("Not Authorized")
 context={}

 groups=request.user.groups.values_list('name',flat = True)
 application_detail = Applicationform.objects.filter(id=app_id)
 trees_species_list = TreeSpecies.objects.all().values('name')
 fod_list = ForestOfficerdetail.objects.filter(range_name__name=application_detail[0].area_range).values_list('fod_user_id',flat=True)
 range_officer = CustomUser.objects.filter(is_delete=False,groups__name='deputy range officer',id__in=fod_list).values('name','id','address')
 geospecies = Species_geodetails.objects.filter(appform_id=app_id).values('species_tree','length','breadth','volume','latitude','longitude')
 image_document=[]
 if image_documents.objects.filter(app_form_id=app_id).exists():
  image_document = image_documents.objects.filter(app_form_id=app_id)[0]
	# if application_detail:
  
 isvehicle = 'Not Applicable'
 is_timberlog=''
 timber_log = Timberlogdetails.objects.filter(appform_id=app_id)
 if timber_log:
  timber_log=timber_log.values()
 else:
  is_timberlog='N/A'
	# transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
 app_status =False
 if application_detail[0].application_status=='A' or application_detail[0].application_status =='R':
  app_status=True
  transit_pass_exist = False
  if groups[0] == "revenue officer" and application_detail[0].verify_office == True:
   transit_pass_exist = True
  elif groups[0] == "deputy range officer" and application_detail[0].depty_range_officer == True:
   transit_pass_exist = True
  elif groups[0] == "forest range officer" and application_detail[0].verify_range_officer == True:
   transit_pass_exist = True
  else:
   pass
  can_assign_deputy=False
  if groups[0] == "forest range officer" and application_detail[0].is_form_two == True and application_detail[0].verify_office == True and application_detail[0].depty_range_officer == False:
		# if application_detail[0].assigned_deputy1 == '' or application_detail[0].assigned_deputy2 == '' :
   if not (application_detail[0].assigned_deputy1_id and application_detail[0].assigned_deputy2_id):
    can_assign_deputy=True
    if application_detail[0].assigned_deputy1_id and application_detail[0].verify_forest1==False:
     can_assign_deputy=True

  if groups[0] == "forest range officer" and application_detail[0].assgn_deputy=='assgned' and application_detail[0].verify_office == True and application_detail[0].depty_range_officer == False:
   if not (application_detail[0].assigned_deputy1_id and application_detail[0].assigned_deputy2_id):
    can_assign_deputy=True
    if application_detail[0].assigned_deputy1_id and application_detail[0].verify_forest1==False:
     can_assign_deputy=True

	# can_assign_deputy=False
	# if groups[0] == "forest range officer" and application_detail[0].assgn_deputy=='assgned' and application_detail[0].verify_office == True and application_detail[0].depty_range_officer == False:
	# 	# if application_detail[0].assigned_deputy1 == '' or application_detail[0].assigned_deputy2 == '' :
	# 	if not (application_detail[0].assigned_deputy1_id and application_detail[0].assigned_deputy2_id):
	# 			can_assign_deputy=True
	# 			if application_detail[0].assigned_deputy1_id and application_detail[0].verify_forest1==False:
	# 				can_assign_deputy=False


  can_deputy_approve=False
  if application_detail[0].verify_office == True and application_detail[0].is_form_two == True and groups[0] == "deputy range officer":
		# if   application_detail[0].assigned_deputy1_id==request.user.id or application_detail[0].assigned_deputy2_id==request.user.id:
		# 	can_deputy_approve=True
   if  application_detail[0].assigned_deputy2_id==request.user.id:
    can_deputy_approve=True
   if  application_detail[0].assigned_deputy1_id==request.user.id and application_detail[0].verify_deputy2==False:
    can_deputy_approve=True
   if application_detail[0].is_form_two==False:
    can_deputy_approve=True
    
 context['app_id'] = app_id
 context['approve_log'] = ApprovedTimberLog.objects.filter(appform_id=app_id)
 context['applied_log'] = Timberlogdetails.objects.filter(appform_id=app_id)

 proof_of_ownership_of_tree_type =  str(application_detail[0].proof_of_ownership_of_tree).split('.')[1]
 revenue_approval_type =  str(image_document.revenue_approval).split('.')[1]
 declaration_type =  str(image_document.declaration).split('.')[1]
 aadhar_detail_type =  str(image_document.aadhar_detail).split('.')[1]
 location_img1_type =  str(image_document.location_img1).split('.')[1]
 location_img2_type =  str(image_document.location_img2).split('.')[1]
 location_img3_type =  str(image_document.location_img3).split('.')[1]
 location_img4_type =  str(image_document.location_img4).split('.')[1]


	
 return render(request,"my_app/tigram/viewapplication.html",{'formtype':'view','applicant':APPLICATION,
		'applications':application_detail,'image_documents':image_document,'groups':groups[0],'app_status':app_status,
  'proof_of_ownership_of_tree_type':proof_of_ownership_of_tree_type,'revenue_approval_type':revenue_approval_type,'declaration_type':declaration_type,'aadhar_detail_type':aadhar_detail_type,
  'location_img1_type':location_img1_type,'location_img2_type':location_img2_type,'location_img3_type':location_img3_type,'location_img4_type':location_img4_type,
		'timber_log':timber_log,'range_officer':list(range_officer),'geospecies':geospecies,
		'trees_species_list':trees_species_list,'isvehicle':isvehicle,'is_timberlog':is_timberlog,'app_id':context['app_id'], 'transit_status':application_detail[0].application_status,
  'is_two':application_detail[0].is_form_two,'approve_log':context['approve_log'],'applied_log':context['applied_log'],'zip':zip(context['applied_log'],context['approve_log']),
  'approve_log_f' : ApprovedTimberLog.objects.filter(appform_id=app_id,is_approved=True),
  })

def assigned_deputy(request):
 groups=request.user.groups.values_list('name',flat = True)
 app_id=request.POST.get('app_id')
 sel_deputy=request.POST.get('sel_deputy')
 try:
  application_detail = Applicationform.objects.filter(id=app_id)
  Applicationform.objects.filter(id=app_id).update(
  	assigned_deputy2_by=request.user,
  	assigned_deputy2_id = sel_deputy,approved_by_r = "Yes",d=sel_deputy,r=request.user,
  	assigned_deputy2_date=date.today()
  )
  return JsonResponse({'message':'Assigned Successfully!'})
 except:
 	return JsonResponse({'message':'Not Assigned Successfully!'})
def assigned_reject(request):
 groups=request.user.groups.values_list('name',flat = True)
 app_id=request.POST.get('app_id')
 try:
  application_detail = Applicationform.objects.filter(id=app_id)
  Applicationform.objects.filter(id=app_id).update(
       r=request.user,verify_forest1=False,verify_deputy=False,verify_range_officer=True,
    application_status = "R",

  )
  return JsonResponse({'message':'Rejected Successfully!'})
 except:
 	return JsonResponse({'message':'Not Assigned Successfully!'})

@login_required

@group_permissions('application_userview')
def application_userview(request,app_id):
 app = Applicationform.objects.get(id=app_id)
 if request.user != app.by_user:
     return HttpResponse("Not Authorized")
 try:
  groups=request.user.groups.values_list('name',flat = True)
  application_detail = Applicationform.objects.filter(id=app_id,by_user=request.user)
  trees_species_list = TreeSpecies.objects.all().values('name')
  image_document=[]
  if image_documents.objects.filter(app_form_id=app_id).exists():
   image_document = image_documents.objects.filter(app_form_id=app_id)[0]
	# if application_detail:
  vehicle = Vehicle_detials.objects.filter(app_form_id=app_id)
  isvehicle=''
  if vehicle:
   vehicle=vehicle[0]
  else:
   isvehicle = 'Not Applicable'
  is_timberlog=''
  timber_log = Timberlogdetails.objects.filter(appform_id=app_id)
  if timber_log:
   timber_log=timber_log.values()
  else:
   is_timberlog='N/A'
	# transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
  transit_pass_exist = False
  if groups[0] == "revenue officer" and application_detail[0].verify_office == True:
   transit_pass_exist = True
  elif groups[0] == "deputy range officer" and application_detail[0].depty_range_officer == True:
   transit_pass_exist = True
  elif groups[0] == "forest range officer" and application_detail[0].verify_range_officer == True:
   transit_pass_exist = True
  else:
   pass
  try:
   proof_of_ownership_of_tree_type =  str(application_detail[0].proof_of_ownership_of_tree).split('.')[1]
   revenue_approval_type =  str(image_document.revenue_approval).split('.')[1]
   declaration_type =  str(image_document.declaration).split('.')[1]
   aadhar_detail_type =  str(image_document.aadhar_detail).split('.')[1]
   location_img1_type =  str(image_document.location_img1).split('.')[1]
   location_img2_type =  str(image_document.location_img2).split('.')[1]
   location_img3_type =  str(image_document.location_img3).split('.')[1]
   location_img4_type =  str(image_document.location_img4).split('.')[1]
  except:
      return render(request,"my_app/tigram/userviewapplication.html",{'formtype':'view','applicant':APPLICATION,
		'applications':application_detail,'image_documents':image_document,'groups':groups,
   'proof_of_ownership_of_tree_type':"",'revenue_approval_type':"",'declaration_type':"",'aadhar_detail_type':"",
  'location_img1_type':"",'location_img2_type':"",'location_img3_type':"",'location_img4_type':"",
		'transit_pass_exist':transit_pass_exist,'vehicle':vehicle,'timber_log':timber_log,
		'trees_species_list':trees_species_list,'isvehicle':isvehicle,'is_timberlog':is_timberlog})
  return render(request,"my_app/tigram/userviewapplication.html",{'formtype':'view','applicant':APPLICATION,
		'applications':application_detail,'image_documents':image_document,'groups':groups,
   'proof_of_ownership_of_tree_type':proof_of_ownership_of_tree_type,'revenue_approval_type':revenue_approval_type,'declaration_type':declaration_type,'aadhar_detail_type':aadhar_detail_type,
  'location_img1_type':location_img1_type,'location_img2_type':location_img2_type,'location_img3_type':location_img3_type,'location_img4_type':location_img4_type,
		'transit_pass_exist':transit_pass_exist,'vehicle':vehicle,'timber_log':timber_log,
		'trees_species_list':trees_species_list,'isvehicle':isvehicle,'is_timberlog':is_timberlog})
 except:
    pass

def application_useredit(request,app_id):

	groups=request.user.groups.values_list('name',flat = True)
	application_detail = Applicationform.objects.filter(id=app_id)
	geospecies_list = Species_geodetails.objects.filter(appform_id=app_id).values_list('species_tree_id',flat=True)
	geospecies = Species_geodetails.objects.filter(appform_id=app_id).values('species_tree_id__name','length','breadth','volume','latitude','longitude')
	trees_species_list = TreeSpecies.objects.filter(id__in=list(geospecies_list),is_noc=False).values('name')
	image_document=[]
	if image_documents.objects.filter(app_form_id=app_id).exists():
		image_document = image_documents.objects.filter(app_form_id=app_id)[0]
	# if application_detail:
	vehicle = Vehicle_detials.objects.filter(app_form_id=app_id)
	isvehicle=''
	if vehicle:
		vehicle=vehicle[0]
	else:
		isvehicle = 'Not Applicable'
	is_timberlog=''
	timber_log = Timberlogdetails.objects.filter(appform_id=app_id)
	if timber_log:
		timber_log=timber_log.values()
	else:
		is_timberlog='N/A'
	# transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
	transit_pass_exist = False
	# if groups[0] == "revenue officer" and application_detail[0].verify_office == True:
	# 	transit_pass_exist = True
	# elif groups[0] == "deputy range officer" and application_detail[0].depty_range_officer == True:
	# 	transit_pass_exist = True
	# elif groups[0] == "forest range officer" and application_detail[0].verify_range_officer == True:
	# 	transit_pass_exist = True
	# else:
	# 	pass
	is_edit=True if application_detail[0].verify_deputy2==True and application_detail[0].depty_range_officer == False else False

	return render(request,"my_app/tigram/user_editapplication.html",{'formtype':'view','applicant':APPLICATION,
		'applications':application_detail,'image_documents':image_document,'groups':groups,'is_edit':is_edit,
		'transit_pass_exist':transit_pass_exist,'vehicle':vehicle,'timber_log':timber_log,'geospecies':geospecies,
		'trees_species_list':trees_species_list,'isvehicle':isvehicle,'is_timberlog':is_timberlog})

@login_required

@group_permissions('edit_application')
def edit_application(request,app_id):
	context = {}
	groups=request.user.groups.values_list('name',flat = True)
	application_detail = Applicationform.objects.filter(id=app_id)
	geospecies_list = Species_geodetails.objects.filter(appform_id=app_id).values_list('species_tree_id',flat=True)
	geospecies = Species_geodetails.objects.filter(appform_id=app_id).values('species_tree_id__name','length','breadth','volume','latitude','longitude')
	# trees_species_list = TreeSpecies.objects.filter(id__in=list(geospecies_list),is_noc=False).values('name')
	if application_detail[0].is_form_two == True:
		trees_species_list = TreeSpecies.objects.filter(id__in=list(geospecies_list),is_noc=False).values('name')
	else:
		trees_species_list = Timberlogdetails.objects.filter(appform_id=app_id).values('species_of_tree')
		# trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
	
	image_document = image_documents.objects.filter(app_form_id=app_id)[0]
	vehicle = Vehicle_detials.objects.filter(app_form_id=app_id)
	isvehicle=''
	if vehicle:
		vehicle=vehicle[0]
	else:
		isvehicle = 'Not Applicable'
	is_timberlog=''
	timber_log = Timberlogdetails.objects.filter(appform_id=app_id)
	if timber_log:
		timber_log=timber_log.values()
	else:
		is_timberlog='N/A'
	# transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
	transit_pass_exist = False
	if groups[0] == "revenue officer" and application_detail[0].verify_office == True:
		transit_pass_exist = True
	elif groups[0] == "deputy range officer" and application_detail[0].depty_range_officer == True:
		transit_pass_exist = True
	elif groups[0] == "forest range officer" and application_detail[0].verify_range_officer == True:
		transit_pass_exist = True
	else:
		pass
	context['app_id'] = app_id
	return render(request,"my_app/tigram/viewapplication.html",{'formtype':'edit','applicant':APPLICATION,
		'applications':application_detail,'image_documents':image_document,'groups':groups,'geospecies':geospecies,
		'transit_pass_exist':transit_pass_exist,'vehicle':vehicle,'timber_log':timber_log,
		'trees_species_list':trees_species_list,'isvehicle':isvehicle,'is_timberlog':is_timberlog,'app_id':context['app_id']
		})

@login_required

@group_permissions('approve_transit_pass')
def approve_transit_pass(request,app_id):
	application_detail = Applicationform.objects.filter(id=app_id)
	groups=request.user.groups.values_list('name',flat = True)
	reason = request.FILES.get('file')
	fi = FileSystemStorage()
	files = fi.save(reason.name, reason)
	if application_detail:
		if application_detail[0].application_status=='R':
			return JsonResponse({'message':'Action cannot be taken, Once Application rejected!','response_code':'warning'})
	else:
		return JsonResponse({'message':'Bad Request!'})
	if request.POST.get('type') == 'REJECT':

		if groups[0] == "revenue officer":
			application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
      disapproved_by=request.user.id,disapproved_by_grp="By Revenue Officer",

				application_status='R',verify_office = True,verify_office_date = date.today())

		elif groups[0] == "deputy range officer":
			# application_detail = Applicationform.objects.filter(id=app_id)

			if application_detail[0].verify_office==True:
				if Applicationform.objects.filter(id=app_id,is_form_two=True).exists():
					if Applicationform.objects.filter(id=app_id,is_form_two=True,verify_deputy2 = True).exists():
						application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
	        		disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
							application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
					else:
						application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
	        		disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
							application_status='R',verify_deputy2 = True,deputy2_date = date.today())
				else:
					application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
	        		disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
							application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
			else:
				JsonResponse({'message':'Application cannot be disapproved as Revenue Officer Action is Pending !','response_code':'warning'})
			# pass
		elif groups[0] == "forest range officer":
			# application_detail = Applicationform.objects.filter(id=app_id)
			if application_detail[0].is_form_two==True:
				if application_detail[0].depty_range_officer==True:
					application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
						disapproved_by=request.user.id,disapproved_by_grp="By Forest Officer",
						application_status='R',verify_range_officer = True,range_officer_date = date.today())
				else:
					if application_detail[0].verify_deputy2==True:
						application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
						disapproved_by=request.user.id,disapproved_by_grp="By Forest Officer",
						application_status='R',verify_forest1 = True,forest1_date = date.today())
					else:
						JsonResponse({'message':'Application cannot be disapproved as Deputy Officer Action is Pending !','response_code':'warning'})
			else:
				if application_detail[0].depty_range_officer==True:
					application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
						disapproved_by=request.user.id,disapproved_by_grp="By Forest Officer",
						application_status='R',verify_range_officer = True,range_officer_date = date.today())
				else:
					JsonResponse({'message':'Application cannot be disapproved as Deputy Officer Action is Pending !','response_code':'warning'})
		elif groups[0] == "division officer":
			# application_detail = Applicationform.objects.filter(id=app_id)
			if application_detail[0].verify_range_officer==True:
				application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
        disapproved_by=request.user.id,disapproved_by_grp="By Division Officer",
					application_status='R',division_officer = True,division_officer_date = date.today())
			else:
				JsonResponse({'message':'Application cannot be disapproved as Forest Range Officer Action is Pending !','response_code':'warning'})
			# pass
		else:
			pass
		return JsonResponse({'message':'Application has been disapproved!','response_code':'error'})
		# return render(request,"my_app/tigram/application_details.html",{'applicant':APPLICATION,'applications':application_detail,'message':'Application has been disapproved!'})


	if application_detail :

		# fi=FileSystemStorage()
		# files=fi.save(reason.name,reason)
		if groups[0] == "revenue officer":
			application_detail.update(
			reason_office = files ,
			application_status = 'P',
			#approved_by = request.user,
			approved_by_revenue = request.user,
			verify_office = True,
			verify_office_date = date.today(),
			# transit_pass_id=transit_pass.id,
			# transit_pass_created_date = datetime.date.today(),
			)
		elif groups[0] == "deputy range officer":
			# if application_detail[0].verify_office==True:
			# 	if application_detail[0].is_form_two==False:
			# 			if application_detail[0].verify_deputy2==False:
			# 				application_detail.update(
			# 			     reason_depty_ranger_office = files ,
			# 			        verify_deputy2 = True, verify_forest1 = True,
			# 			            approved_by_deputy = request.user, approved_by_deputy2 = request.user,
			# 		               	depty_range_officer = True,
			# 			                   deputy_officer_date = date.today(),
			# 		                        	)
			application_detail.update(
						reason_depty_ranger_office = files ,
						        verify_deputy2 = True, verify_forest1 = True,
						            approved_by_deputy = request.user, approved_by_deputy2 = request.user,
					               	depty_range_officer = True,status = True,
						                   deputy_officer_date = date.today(),
						)
			# else:
			# 	JsonResponse({'message':'Application cannot be approved as Revenue Officer Approval is Pending !','response_code':'warning'})

		elif groups[0] == "forest range officer":
			if application_detail[0].is_form_two==False :
						qr_code=get_qr_code(app_id)
						qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
						is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
						if is_timber:
							for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
								log_qr_code=get_log_qr_code(app_id,each_timber['id'])
								log_data='Log Details:\n'
								log_data+='Application No. :-'+application_detail[0].application_no+'\n'
								log_data+='Destination :-'+application_detail[0].destination_details+'\n'
								log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
								log_data+='Length :-'+str(each_timber['length'])+'\n'
								log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
								log_data+='Volume :-'+str(each_timber['volume'])+'\n'
								log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
								log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
								log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
								is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img) 
						application_detail.update(
							reason_range_officer = files ,
							application_status = 'P',
							approved_by = request.user,
							range_officer_date = date.today(),
                            depty_range_officer = True,
							location_needed=True,
                            verify_range_officer = True,
							transit_pass_created_date = date.today(),verify_forest1 = True,
								forest1_date = date.today())
			if application_detail[0].status==True:
					# if application_detail[0].depty_range_officer==True:
						application_detail.update(
							# reason_range_officer = files ,
							application_status = 'A',
							# approved_by = request.user,
							# verify_range_officer = True,
							range_officer_date = date.today(),
								)
			# 		elif application_detail[0].verify_deputy2==True:
			# 			application_detail.update(
			# 					reason_forest1 = files ,
			# 					application_status = 'P',
			# 					approved_by_forest1 = request.user,
			# 					verify_forest1 = True,
			# 					forest1_date = date.today(),
			# 					)
			else:
				JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !','response_code':'warning'})
		elif groups[0] == "division officer":
			if application_detail[0].verify_range_officer==True:
				if application_detail[0].other_state == True:
					if application_detail[0].is_form_two == False:
						qr_code=get_qr_code(app_id)
						qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
						is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
						if is_timber:
							for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
								log_qr_code=get_log_qr_code(app_id,each_timber['id'])

								log_data='Log Details:\n'
								log_data+='Application No. :-'+application_detail[0].application_no+'\n'
								log_data+='Destination :-'+application_detail[0].destination_details+'\n'
								log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
								log_data+='Length :-'+str(each_timber['length'])+'\n'
								log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
								log_data+='Volume :-'+str(each_timber['volume'])+'\n'
								log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
								log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
								log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
								is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img)

						if vehicle_detail:
							# vehicle=vehicle_detail[0]
							transit_pass=TransitPass.objects.create(
								vehicle_reg_no=vehicle_detail[0].vehicle_reg_no,
								driver_name = vehicle_detail[0].driver_name,
								driver_phone = vehicle_detail[0].driver_phone,
								mode_of_transport = vehicle_detail[0].mode_of_transport,
								license_image = vehicle_detail[0].license_image,
								photo_of_vehicle_with_number = vehicle_detail[0].photo_of_vehicle_with_number,
								state = application_detail[0].state,
								district = application_detail[0].district,
								taluka = application_detail[0].taluka,
								block = application_detail[0].block,
								village = application_detail[0].village,
								qr_code = qr_code,
								qr_code_img =qr_img,
								app_form_id = app_id
							)
						else:
							transit_pass=TransitPass.objects.create(
								state = application_detail[0].state,
								district = application_detail[0].district,
								taluka = application_detail[0].taluka,
								block = application_detail[0].block,
								village = application_detail[0].village,
								qr_code = qr_code,
								qr_code_img =qr_img,
								app_form_id = app_id
							)
						application_detail.update(
							reason_division_officer = files ,
							application_status = 'ADE',
							approved_by_division = request.user,
							division_officer = True,
							division_officer_date = date.today(),
							transit_pass_id=transit_pass.id,
							transit_pass_created_date = date.today(),
							)
					else:
						application_detail.update(
							reason_division_officer = files ,
							application_status = 'P',
							approved_by_division = request.user,
							division_officer = True,
							division_officer_date = date.today(),
							# transit_pass_id=transit_pass.id,
							# transit_pass_created_date = date.today(),
							)
				else:
					JsonResponse({'message':'Application cannot be approved !','response_code':'warning'})
					# JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
			# application_detail[0].save()
			else:

					JsonResponse({'message':'Application cannot be approved as Forest Range Officer Approval is Pending !','response_code':'warning'})
		else:
			pass
	return JsonResponse({'message':'Application has been approved!','response_code':'success'})
	# return render(request,"my_app/tigram/application_details.html",{'applicant':APPLICATION,'applications':application_detail})


@login_required

@group_permissions('check_status')
def check_status(request):
 from datetime import date
 context={}
 groups=request.user.groups.values_list('name',flat = True)
 context['group'] = groups
 # application = Applicationform.objects.filter(by_user_id=request.user.id,is_noc=False,is_form_two=False).order_by('-id')
 application = Applicationform.objects.filter(by_user_id=request.user.id,is_noc=False).order_by('-id')
 
 tp = TransitPass.objects.filter(app_form__by_user_id=request.user.id).order_by('-app_form_id')

 incr=1
 applicant=[]
 tp_list = []
 for each in application:
  checkstatus = {}
  checkstatus['sr'] =incr
  checkstatus['applicant_no'] = each.id
  checkstatus['application_no'],checkstatus['current_app_status'] = each.application_no ,each.current_app_status
  checkstatus['created_date'] = each.created_date
  checkstatus['application_status'] = each.get_application_status_display()
  checkstatus['depty_range_officer'] = each.depty_range_officer
  checkstatus['new_remarks'] = ""
  if each.range_1_text != "":
      checkstatus['new_remarks'] =each.range_1_text
  if each.deputy_verify_text != "":
     checkstatus['new_remarks']= each.deputy_verify_text
  if each.range_2_text != "":
     checkstatus['new_remarks']= each.range_2_text
  if each.reason_division_officer != '':
   checkstatus['remark'] =  each.reason_division_officer
   checkstatus['remark_date']= each.division_officer_date
  elif each.reason_range_officer != '':
   checkstatus['remark'] =  each.reason_range_officer
   checkstatus['remark_date']= each.range_officer_date
  elif each.reason_depty_ranger_office != '':
   checkstatus['remark'] =  each.reason_depty_ranger_office
   checkstatus['remark_date']= each.deputy_officer_date
  elif each.reason_forest1 != '':
   checkstatus['remark'] =  each.reason_forest1
   checkstatus['remark_date']= each.forest1_date
  elif each.reason_deputy2 != '':
   checkstatus['remark'] =  each.reason_deputy2
   checkstatus['remark_date']= each.deputy2_date
  elif each.reason_office != '':
   checkstatus['remark'] =  each.reason_office
   checkstatus['remark_date']= each.verify_office_date
  else:
   checkstatus['remark'] =  'N/A'
   checkstatus['remark_date']= 'N/A'
  if each.application_status == 'R' :
  	checkstatus['remark'] = each.disapproved_reason
  checkstatus['is_form_two'] =each.is_form_two  
  if each.is_form_two == True:
  	if each.assigned_deputy2 !=None:
  	 checkstatus['assigned_deputy']=each.assigned_deputy2.name
  	elif each.assigned_deputy1 !=None :
  	 checkstatus['assigned_deputy']='Yet to Assign for Stage 2' if each.log_updated_by_user == True else each.assigned_deputy1.name
  	else:
  	 checkstatus['assigned_deputy']= 'Yet to Assign for Stage 1'
  if each.application_status != 'A':
  	checkstatus['expiry_date'] = 'Not Generated'
  else:
   date_1 = datetime.strptime(str(each.transit_pass_created_date), "%Y-%m-%d")
   checkstatus['expiry_date'] = date_1 + timedelta(days=7)
  checkstatus['tp_number'] = 'Not Generated' if each.application_status != 'A' else each.transit_pass_id
  checkstatus['edit_log'] =False
  applicant.append(checkstatus)
  incr = incr+1
 	# checkstatus[incr]=applicant
 noc_application = Applicationform.objects.filter(by_user_id=request.user.id,is_noc=True).order_by('-id')
 incr1=1
 noc_applicant=[]
 for each in noc_application:
 	checkstatus = {}
 	checkstatus['sr'] =incr
 	checkstatus['applicant_no'] = each.id
 	checkstatus['application_no'] = each.application_no
 	checkstatus['created_date'] = each.created_date
 	noc_applicant.append(checkstatus)
 	incr1 = incr1+1
 return render(request,"my_app/tigram/checkstatus.html",{'application':applicant,'noc_application':noc_applicant,'groups':context['group'],'tp':tp})
 
def random_generate_number(size, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

def get_qr_code(app_id):
	stringdata = '1234567890ABCDEFGHIJKLMNPSTUVWXYZ'
	generate_number = 'SA'+str(app_id)+random_generate_number(12, stringdata)
	code_exist = TransitPass.objects.filter(qr_code__iexact=generate_number)
	if code_exist:
		generate_number = get_qr_code()
	return generate_number

def generate_qrcode_image(qrcode_string, qrcode_path, record_id):

	image_name = 'QR_'+str(qrcode_string)+'_PR_'+str(record_id)+'.png'
	#image_path = settings.QRCODE_PATH
	image_path = qrcode_path
	image_file = str(image_path)+str(image_name)

	try:

		qr = qrcode.QRCode(border=4)
		qrcode_string = settings.SERVER_BASE_URL+'app/scanqr/'+qrcode_string
		qr.add_data(qrcode_string)
		qr.make(fit=True)
		#img = qr.make_image(fill_color="red", back_color="#23dda0")
		img = qr.make_image()
		img.save(image_file)
	except Exception as error:
		image_name = ''

	return image_name
def generate_qrcode_transit(qrcode_string, qrcode_path, record_id):

	image_name = 'QR_'+str(qrcode_string)+'_PR_'+str(record_id)+'.png'
	#image_path = settings.QRCODE_PATH
	image_path = qrcode_path
	image_file = str(image_path)+str(image_name)

	try:

		qr = qrcode.QRCode(border=4)
		qrcode_string = settings.SERVER_BASE_URL+'app/transit_pass_pdf/'+qrcode_string
		qr.add_data(qrcode_string)
		qr.make(fit=True)
		#img = qr.make_image(fill_color="red", back_color="#23dda0")
		img = qr.make_image()
		img.save(image_file)
	except Exception as error:
		image_name = ''

	return image_name

def get_log_qr_code(app_id,log_id):
	stringdata = '1234567890ABCDEFGHIJKLMNPSTUVWXYZ'
	generate_number = 'TLOG'+str(app_id)+'_'+random_generate_number(12, stringdata)+'_'+str(log_id)
	code_exist = Timberlogdetails.objects.filter(log_qr_code__iexact=generate_number)
	if code_exist:
		generate_number = get_log_qr_code(app_id,log_id)
	return generate_number

def generate_log_qrcode_image(qrcode_string, qrcode_path, record_id,log_data):

	image_name = 'QR_'+str(qrcode_string)+'.png'
	#image_path = settings.QRCODE_PATH
	image_path = qrcode_path
	image_file = str(image_path)+str(image_name)

	try:

		qr = qrcode.QRCode(border=4)
		# log_data={}
		# 				log_data['parent_tp_app_no']=application_detail[0].application_no
		# 				log_data['destination_details']=application_detail[0].destination_details
		# 				log_data['species']=each_timber['species_of_tree']
		# 				log_data['latitude']=each_timber['latitude']
		# 				log_data['longitude']=each_timber['longitude']
		# 				log_data['length']=each_timber['length']
		# 				log_data['breadth']=each_timber['breadth']
		# 				log_data['volume']=each_timber['volume']
		# 				log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
		qrcode_string = settings.SERVER_BASE_URL+'app/scan_logqr/'+qrcode_string
		# qrcode_string = log_data
		qr.add_data(qrcode_string)
		qr.make(fit=True)
		#img = qr.make_image(fill_color="red", back_color="#23dda0")
		img = qr.make_image()
		img.save(image_file)
	except Exception as error:
		image_name = ''

	return image_name

@login_required
@group_required('revenue officer','deputy range officer','forest range officer')

def disapprove_transit_pass(request,app_id):
	reason = request.POST.get('reason')
	application_detail = Applicationform.objects.filter(id=app_id).update(reason_range_officer=reason,application_status='R')

	return render(request,"my_app/tigram/application_details.html",{'applicant'})

def generate_pdf(src,name):
	pdf = pdfkit.from_url(src, False)
	response = HttpResponse(pdf,content_type='application/pdf')
	response['Content-Disposition'] = 'attachment; filename='+name+'.pdf'
	return response

@login_required
def user_report12(request,applicant_no):
	logo1=settings.DEFAULT_LOGO
	logo2 = settings.DEFAULT_LOGO
	groups=request.user.groups.values_list('name',flat = True)
	transitpass = TransitPass.objects.filter(app_form_id=applicant_no)
	qr_img=''
	is_transitpass='ok'
	if transitpass:
		transitpass=transitpass[0]
	# log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
	# signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
		qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
	else:
		qr_img = ''
		is_transitpass='Not Generated'
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# pdf = pdfkit.from_string(wt, False,configuration=config)
	template =''
	if groups[0] in ['revenue officer','deputy range officer','forest range officer']:
		template = get_template("pdf_template/report.html")
	else:
		template = get_template("pdf_template/userreport.html")
	application = Applicationform.objects.filter(id=applicant_no).values()
	if application:
		context = {'application':application,"logo1":logo1,"logo2":logo2,
		'qr_img':qr_img,'transitpass':transitpass,'is_transitpass':is_transitpass}  # data is the context data that is sent to the html file to render the output.
		html = template.render(context)  # Renders the template with the context data.
		pdf = pdfkit.from_string(html, False)
		# pdf = pdfkit.from_string(html, False, configuration=config)
		# pdf = open("summaryreport.pdf")
		response = HttpResponse(pdf, content_type='application/pdf')  # Generates the response as pdf response.
		response['Content-Disposition'] = 'attachment; filename=UserReport.pdf'
		# pdf.close()
		# os.remove("summaryreport.pdf")  # remove the locally created pdf file.
		return response
	else:
		# message = "No Data Found"
		return HttpResponseRedirect(reverse('officer_dashboard'))


@login_required
@group_permissions('update_timberlog')
def update_timberlog(request,applicant_no):
	application =applicant_no# request.POST.get('app_form_id')
	log_id = request.POST.getlist('log_id[]')
	species = request.POST.getlist('update-species[]')
	length = request.POST.getlist('update-length[]')
	breadth = request.POST.getlist('update-breadth[]')
	volume = request.POST.getlist('update-volume[]')

	if request.user.is_authenticated:
		groups=request.user.groups.values_list('name',flat = True)
		if groups[0] == 'user':
			if Applicationform.objects.filter(id=applicant_no)[0].verify_forest1==True:
				Applicationform.objects.filter(id=applicant_no).update(appsecond_two_date=date.today(),log_updated_by_user=True)
			else:
				# timber_log=Species_geodetails.objects.filter(appform_id=applicant_no).values()
				return JsonResponse({'message':'Need Forest Range Officer Approval!!!'})
	tlog_exist = Timberlogdetails.objects.filter(appform=application)
	if tlog_exist:
		tlog_exist.delete()
	tlog=[]
	if len(species) >0 :
		for i in range(len(species)):
			timber = Timberlogdetails(appform_id=application,species_of_tree=species[i],
			length=length[i],volume=volume[i], breadth=breadth[i]
			)
			tlog.append(timber)
		Timberlogdetails.objects.bulk_create(tlog)
	timber_log=Timberlogdetails.objects.filter(appform_id=applicant_no).values()
		# application.save()
	return JsonResponse({'message':'Updated successfully!!!','timber_log':list(timber_log)})

@login_required
def load_timberlog(request,applicant_no):
	timber_log=Timberlogdetails.objects.filter(appform_id=applicant_no).values()
	return render(request,'my_app/tigram/timber_log_template.html',{'timber_log':timber_log})


def index(request):
	context={}
	context['group'] = "reg"
	if request.user.is_authenticated:
		groups=request.user.groups.values_list('name',flat = True)
		# user= CustomUser.objects.filter(id=request.user.id)
		context['group'] = groups[0]
	# context['no_of_tp'] = TransitPass.objects.all().count()
	# context['no_of_tp'] = Applicationform.objects.exclude(transit_pass_id__exact='').count()
	context['no_of_app']=Applicationform.objects.all().count()
	context['no_of_tp'] = Applicationform.objects.all().exclude(transit_pass_id=0).count()
	context['no_of_tp_pending'] = Applicationform.objects.filter(Q(application_status='S')|Q(application_status='P')).exclude(~Q(transit_pass_id=0)).count()
	context['no_of_tp_rejected'] = Applicationform.objects.filter(application_status='R').count()
	return render(request,"my_app/tigram/index.html",context)

import json
@login_required
@group_permissions('edit_profile')
def edit_profile(request,user_id):
 if request.user.id != user_id:
  return HttpResponse("Not Authorized")
 context={}
 count = {}
 count['no_of_app']=Applicationform.objects.all().count()
 count['no_of_tp'] = TransitPass.objects.all().count()
 count['no_of_tp_pending'] = Applicationform.objects.filter(Q(application_status='S')|Q(application_status='P')).count()
 count['no_of_tp_rejected'] = Applicationform.objects.filter(application_status='R').count()
 groups=request.user.groups.values_list('name',flat = True)
 user= CustomUser.objects.filter(id=user_id)
 context['group'] = groups
 if request.method == "POST":
  name = request.POST["name"]
  address = request.POST["address"]
 
  if check_sanitization(name,address) == True:
   pass
  else:
   user=user[0]
   return render(request,"my_app/tigram/profile.html",{'user':user,'groups':context['group'],'count':count}) 
  try :
   file = request.FILES['user_profile_pic']
   picccc = upload_new_user_image_file(user_id,file)
   user.update(
		name=name,
		address=address,
        profile_pic = picccc
		)
  except:
      user.update(
		name=name,
		address=address,
      
		)
  return redirect('view_profile',user_id)
 else :
  user=user[0]
 return render(request,"my_app/tigram/profile.html",{'user':user,'groups':context['group'],'count':count})


@login_required
@group_permissions('view_profile')
def view_profile(request,user_id):
 if request.user.id != user_id:
  return HttpResponse("Not Authorized")
 context={}
 count = {}
 count['no_of_app']=Applicationform.objects.all().count()
 count['no_of_tp'] = TransitPass.objects.all().count()
 count['no_of_tp_pending'] = Applicationform.objects.filter(Q(application_status='S')|Q(application_status='P')).count()
 count['no_of_tp_rejected'] = Applicationform.objects.filter(application_status='R').count()
 groups=request.user.groups.values_list('name',flat = True)
 context['group'] = groups

 user= CustomUser.objects.filter(id=user_id)[0]
 return render(request,"my_app/tigram/profile.html",{'user':user,'groups':context['group'],'count':count})
def link_callback(uri, rel):
            """
            Convert HTML URIs to absolute system paths so xhtml2pdf can access those
            resources
            """
            result = finders.find(uri)
            if result:
                    if not isinstance(result, (list, tuple)):
                            result = [result]
                    result = list(os.path.realpath(path) for path in result)
                    path=result[0]
            else:
                    sUrl = settings.STATIC_URL        # Typically /static/
                    sRoot = settings.STATIC_ROOT      # Typically /home/userX/project_static/
                    mUrl = settings.MEDIA_URL         # Typically /media/
                    mRoot = settings.MEDIA_ROOT       # Typically /home/userX/project_static/media/

                    if uri.startswith(mUrl):
                            path = os.path.join(mRoot, uri.replace(mUrl, ""))
                    elif uri.startswith(sUrl):
                            path = os.path.join(sRoot, uri.replace(sUrl, ""))
                    else:
                            return uri

           
            return path
def link_callback2(uri, rel):
            """
            Convert HTML URIs to absolute system paths so xhtml2pdf can access those
            resources
            """
            result = finders.find(uri)
            if result:
                    if not isinstance(result, (list, tuple)):
                            result = [result]
                    result = list(os.path.realpath(path) for path in result)
                    path=result[0]
            else:
                    sUrl = settings.STATIC_URL        # Typically /static/
                    sRoot = settings.STATIC_ROOT      # Typically /home/userX/project_static/
                    mUrl = settings.MEDIA_URL         # Typically /media/
                    mRoot = settings.MEDIA_ROOT       # Typically /home/userX/project_static/media/

                    if uri.startswith(mUrl):
                            path = os.path.join(mRoot, uri.replace(mUrl, ""))
                    elif uri.startswith(sUrl):
                            path = os.path.join(sRoot, uri.replace(sUrl, ""))
                    else:
                            return uri

            # make sure that file exists
            
            return path
import os
from django.conf import settings
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.contrib.staticfiles import finders
from xhtml2pdf import pisa

from django.template.loader import get_template
from django.template import Context
def transit_pass_pdf2(request,applicant_no):
	logo1=settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
	logo2 = settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
	image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
	transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
	log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
	signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
	qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
	main_url=settings.SERVER_BASE_URL

	application = Applicationform.objects.filter(id=applicant_no).values()
	# if application:
	context = {'applications':application,"logo1":logo1,"logo2":logo2,
		'signature_img':signature_img,'qr_img':qr_img,
		'transitpass':transitpass,'log_details':log_details}
	pdf = render_to_pdf('pdf_template/transitpass.html',context)
		# return HttpResponse(result.getvalue(), content_type='application/pdf')
	response = HttpResponse(pdf, content_type='application/pdf')
	filename = "TransitPass.pdf"
	content = "attachment; filename='%s'" %(filename)
	response['Content-Disposition'] = content
	return response
	# response = HttpResponse(pdf, content_type='application/pdf')
	# filename = "Invoice_%s.pdf" %("12341231")
	# content = "attachment; filename='%s'" %(filename)
	# response['Content-Disposition'] = content
	# return response
@login_required
@group_permissions('transit_pass_pdf')
def transit_pass_pdf(request,tpass):
 logo1 ,logo2 , logo3 ,logo4= settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/USAID__LOGO.jpeg",settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/KeralaForest.png",settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/MINISTRY_LOGO2.png",settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/tigram_logo02.png"
 qrrr = get_qr_string(settings.SERVER_BASE_URL+"gettransitpassqr/"+str(tpass))
 transit = TransitPass.objects.get(transit_number=tpass)
 qr_img = settings.SERVER_BASE_URL+'/static/media/qr_code/'+ str(transit.qr_code_img)
 if transit.transit_status == "Approved":
  application = Applicationform.objects.get(id = transit.app_form.id)
  if request.user.is_authenticated:
   if request.user.is_staff:
    pass
   elif request.user == application.by_user:
    pass
   else:
       return HttpResponse(request,"No Access")    
  else:
      return HttpResponse(request,"No Access")
  if application:
   authorizer_name = application.r.name if application.is_noc==False and application.deemed_approval==False else 'N/A'
   image_document = image_documents.objects.get(app_form=application)
   log_details = ProductTransit.objects.filter(transit_pass=transit,is_transit_approved=1).values()
   date_1 = transit.transit_req_date
   main_url=settings.SERVER_BASE_URL+'static/media/qr_code/'
   expiry_date = date_1 + timedelta(days=7)
   
   context = {'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,"logo4":logo4,'main_url':main_url,
  	'qr_img':qr_img,'authorizer_name':authorizer_name,
  	'transitpass':transit,'log_details':log_details,'expiry_date':expiry_date,'qrrr':qrrr}
  
  
   response = HttpResponse(content_type='application/pdf')

   today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')

   filename= 'TransitPass-'+str(application.application_no)+'-'+today_stamp+''
   response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'

   template = get_template('pdf_template/newtransitpass_tbl.html')
   html = template.render(context)
  
  # create a pdf
   pisa_status = pisa.CreatePDF(
  	html, dest=response, link_callback=link_callback)
  # if error then show some funy view
   if pisa_status.err:
    return HttpResponse('We had some errors <pre>' + html + '</pre>')
   return response
  else:
   return HttpResponseRedirect(reverse('dashboard'))
 return HttpResponseRedirect(reverse('dashboard'))


@login_required
@group_permissions('transit_pass_pdf')
def cutting_pass_pdf(request,app_id):
 logo1 ,logo2 , logo3 ,logo4= settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/USAID__LOGO.jpeg",settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/KeralaForest.png",settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/MINISTRY_LOGO2.png",settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/tigram_logo02.png"

 qrrr = get_qr_string(settings.SERVER_BASE_URL+"getcuttingpassqr/"+str(app_id))
 application = Applicationform.objects.get(id = app_id)
 if application:
  if application.r:
     authorizer_name = application.r.name 
  elif application.f_r:  
      authorizer_name = application.f_r.name
#    authorizer_name = CustomUser.objects.get(id= application.f_r).name 
  else:
    authorizer_name = 'N/A'
  image_document = image_documents.objects.get(app_form=application)
  log_details = ApprovedTimberLog.objects.filter(appform_id=application,is_approved =True).values()
  signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
  #qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(application.qr_code_img)

  main_url=settings.SERVER_BASE_URL+'static/media/qr_code/'

  context = {'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,"logo4":logo4,'qrrr':qrrr,
  	'signature_img':signature_img,'authorizer_name':authorizer_name,'log_details':log_details}
  
  
  
  response = HttpResponse(content_type='application/pdf')

  today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')

  filename= 'Cutting_Pass-'+str(application.application_no)+'-'+today_stamp+''
  response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'

  template = get_template('pdf_template/newcuttingpass_tbl.html')
  html = template.render(context)
  
  # create a pdf
  pisa_status = pisa.CreatePDF(
  	html, dest=response, link_callback=link_callback2)
  # if error then show some funy view
  if pisa_status.err:
  	return HttpResponse('We had some errors <pre>' + html + '</pre>')
  return response
 else:
  return HttpResponseRedirect(reverse('dashboard'))
def get_log_qr_details(request,app_id):
	application = Applicationform.objects.filter(id=app_id)
	if application:
		authorizer_name = application[0].approved_by.name
		application=application.values()

		transitpass = TransitPass.objects.filter(app_form_id=app_id).values()
		log_details = Timberlogdetails.objects.filter(appform_id=app_id).values()
		# signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)

		# qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)

		# date_1 = datetime.datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
		# date_1 = datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
		main_url = settings.SERVER_BASE_URL+"""static/media/qr_code/"""
		req_url=request.META['HTTP_HOST']
		# expiry_date = date_1 + datetime.timedelta(days=7)
		# expiry_date = date_1 + timedelta(days=7)
		context = {"req_url":req_url,
			'transitpass':list(transitpass),'log_details':list(log_details)}
		return JsonResponse(context,safe=False)


@login_required
@group_permissions('log_qrcode_pdf')
def log_qrcode_pdf(request,log_no):
	# logo1=settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
	logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
  #logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.jpg"
	logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
	logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
	log_details = Timberlogdetails.objects.filter(id=log_no)
	if log_details:
		# authorizer_name = log_details[0].approved_by.name
		# log_details=log_details.values()
		# log_code=

		# signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
		# qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
		# date_1 = datetime.datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
		# date_1 = datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
		# qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(log_details[0].log_qr_code_img)
		# qr_img = "http://localhost:8000/"+"""static/media/qr_code/"""+ str(log_details[0].log_qr_code_img)
		qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(log_details[0].log_qr_code_img)

		main_url = settings.SERVER_BASE_URL+"""static/media/qr_code/"""
		req_url=request.META['HTTP_HOST']
		# expiry_date = date_1 + datetime.timedelta(days=7)
		# expiry_date = date_1 + timedelta(days=7)
		context = {'log_details':log_details[0],"logo1":logo1,"logo2":logo2,"logo3":logo3,
		"qr_img":qr_img,"req_url":req_url}

		response = HttpResponse(content_type='application/pdf')
		today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
		filename= 'Log_Details-'+str(log_details[0].appform.application_no)+'-'+today_stamp+''
		response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'
		# find the template and render it.
		template = get_template('pdf_template/log_qr_details.html')
		html = template.render(context)

		# create a pdf
		pisa_status = pisa.CreatePDF(
			html, dest=response, link_callback=link_callback)
		# if error then show some funy view
		if pisa_status.err:
			return HttpResponse('We had some errors <pre>' + html + '</pre>')
		return response
	else:
		return HttpResponseRedirect(reverse('dashboard'))

@login_required
@group_permissions('qr_code_pdf')
def qr_code_pdf(request,applicant_no):
	# logo1=settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
	logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
	logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
	logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
  #logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.jpg"
	# image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
	# transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
	# log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
	# signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
	# qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)

	application = Applicationform.objects.filter(id=applicant_no)
	if application:
		authorizer_name = application[0].approved_by.name
		application=application.values()

		transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
		log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
		# signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
		qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
		# date_1 = datetime.datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
		date_1 = datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
		main_url = settings.SERVER_BASE_URL+'static/media/qr_code/'
		req_url=request.META['HTTP_HOST']
		# expiry_date = date_1 + datetime.timedelta(days=7)
		expiry_date = date_1 + timedelta(days=7)
		context = {'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,"req_url":req_url,'main_url':main_url,
			'transitpass':transitpass,'log_details':log_details}

		response = HttpResponse(content_type='application/pdf')
		today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
		filename= 'QRCodes-'+str(application[0]['application_no'])+'-'+today_stamp+''
		response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'
		# find the template and render it.
		template = get_template('pdf_template/log_newqrcode.html')
		html = template.render(context)

		# create a pdf
		pisa_status = pisa.CreatePDF(
			html, dest=response, link_callback=link_callback)
		# if error then show some funy view
		if pisa_status.err:
			return HttpResponse('We had some errors <pre>' + html + '</pre>')
		return response
	else:
		return HttpResponseRedirect(reverse('dashboard'))

@login_required
@group_permissions('user_report')
def user_report(request,applicant_no):
 logo1= settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/USAID__LOGO.jpeg"
 logo2 = settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/KeralaForest.png"
 logo3= settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/MINISTRY_LOGO2.png"
 logo4 = settings.SERVER_BASE_URL+"home/ubuntu/timberproject/static/images/tigram_logo02.png"
#  logo2 = settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
 qrrr = get_qr_string(settings.SERVER_BASE_URL+"getuserreportqr/"+str(applicant_no))
 groups=request.user.groups.values_list('name',flat = True)
 transitpass = TransitPass.objects.filter(app_form_id=applicant_no)
 qr_img=''
 is_transitpass='ok'
 if transitpass:
  transitpass=transitpass[0]
  qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
 else:
  qr_img = ''
  is_transitpass='Not Generated'
 template =''
 if groups[0] in ['revenue officer','deputy range officer','forest range officer']:
  template = get_template("pdf_template/newreport.html")
 else:
  template = get_template("pdf_template/newreport.html")
 application = Applicationform.objects.filter(id=applicant_no).values()
 if application:
  approved_names = Applicationform.objects.filter(id=applicant_no).values('approved_by_division__name','approved_by_deputy__name','approved_by_deputy2__name','assigned_deputy1_by__name','assigned_deputy2_by__name','approved_by_forest1__name','approved_by_revenue__name','approved_by__name')
  date_1 = datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
  expiry_date = date_1 + timedelta(days=7)
  context = {'qrrr':qrrr,'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,"logo4":logo4,'expiry_date':expiry_date,
  'qr_img':qr_img,'transitpass':transitpass,'is_transitpass':is_transitpass,'approved_names':list(approved_names)}  # data is the context data that is sent to the html file to render the output.
  response = HttpResponse(content_type='application/pdf')
  today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
  filename= 'UserReport-'+str(application[0]['application_no'])+'-'+today_stamp+''
  response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'
  html = template.render(context)
  pisa_status = pisa.CreatePDF(
	html, dest=response, link_callback=link_callback)
  if pisa_status.err:
   return HttpResponse('We had some errors <pre>' + html + '</pre>')
  return response
 else:
  return HttpResponseRedirect(reverse('dashboard'))


@login_required
def transit_pass_pdf1(request,applicant_no):
	logo1 ,logo2 , logo3 ,logo4= "http://127.0.0.1:8000/static/images/USAID__LOGO.jpeg","http://127.0.0.1:8000/static/images/KeralaForest.png","http://127.0.0.1:8000/static/images/MINISTRY_LOGO2.png","http://127.0.0.1:8000/static/images/tigram_logo02.png"
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# pdf = pdfkit.from_string(wt, False,configuration=config)
	template = get_template("pdf_template/transitpass.html")
	# css = os.path.join(settings.STATIC_URL, 'css/summaryreport.css', 'summaryreport.css')
	# applications = Applicationform.objects.all().order_by('-id')
	application = Applicationform.objects.filter(id=applicant_no)
	if application:
		application=application.values()
		image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
		transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
		log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
		signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
		qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
		date_1 = datetime.datetime.strptime(str(application[0].transit_pass_created_date), "%Y-%m-%d")
		expiry_date = date_1 + datetime.timedelta(days=7)
		context = {'application':application,"logo1":logo1,"logo2":logo2,
			'signature_img':signature_img,'qr_img':qr_img,
			'transitpass':transitpass,'log_details':log_details,'expiry_date':expiry_date}  # data is the context data that is sent to the html file to render the output.
		html = template.render(context)  # Renders the template with the context data.
		pdf = pdfkit.from_string(html, False)
		# pdf = pdfkit.from_string(html, False, configuration=config)
		# pdf = open("summaryreport.pdf")
		response = HttpResponse(pdf, content_type='application/pdf')  # Generates the response as pdf response.
		response['Content-Disposition'] = 'attachment; filename=transitpass.pdf'
		# pdf.close()
		# os.remove("summaryreport.pdf")  # remove the locally created pdf file.
		return response
	else:
		# message = "No Data Found"
		return HttpResponseRedirect(reverse('officer_dashboard'))

@login_required
def transit_pass_pdf2(request,applicant_no):
	logo1=settings.DEFAULT_LOGO
	logo2 = settings.DEFAULT_LOGO
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# pdf = pdfkit.from_string(wt, False,configuration=config)
	template = get_template("pdf_template/transitpass.html")
	# css = os.path.join(settings.STATIC_URL, 'css/summaryreport.css', 'summaryreport.css')
	# applications = Applicationform.objects.all().order_by('-id')
	application = Applicationform.objects.filter(id=applicant_no).values()
	if application:
		image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
		transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
		log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
		signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
		qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
		context = {'application':application,"logo1":logo1,"logo2":logo2,
			'signature_img':signature_img,'qr_img':qr_img,
			'transitpass':transitpass,'log_details':log_details}  # data is the context data that is sent to the html file to render the output.
		html = template.render(context)  # Renders the template with the context data.
		pdf = pdfkit.from_string(html, False)
		# pdf = pdfkit.from_string(html, False, configuration=config)
		# pdf = open("summaryreport.pdf")
		response = HttpResponse(pdf, content_type='application/pdf')  # Generates the response as pdf response.
		response['Content-Disposition'] = 'attachment; filename=transitpass.pdf'
		# pdf.close()
		# os.remove("summaryreport.pdf")  # remove the locally created pdf file.
		return response
	else:
		# message = "No Data Found"
		return HttpResponseRedirect(reverse('officer_dashboard'))


@login_required
@group_required('revenue officer','deputy range officer','forest range officer')
def view_summary_report(request):
	applications = Applicationform.objects.all().order_by('-id')


	return render(request,"my_app/tigram/summaryreport.html",{'applications':applications})

def load_division(request):
	range_area = request.GET.get('area_range')
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	if range_area.isdigit():
		div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	else:
		div_list = list(Range.objects.filter(name__iexact=range_area).values('name'))

	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	return JsonResponse({'div_list':div_list})

def load_division1(request):
	range_area = request.GET.get('range_area')
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	if range_area.isdigit():
		div_list = list(Range.objects.filter(division_id=range_area).values('id','name'))
	else:
		div_list = list(Range.objects.filter(division__name__iexact=range_area).values('name'))
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	return JsonResponse({'div_list':div_list})

def load_checkpost(request):
	range_area = request.GET.get('range_area')
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	if range_area.isdigit():

		div_list = list(CheckPost.objects.filter(range_name_id=range_area).values('id','checkpost_name'))
	else:
		div_list = list(CheckPost.objects.filter(range_name__name__iexact=range_area).values('checkpost_name'))
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	return JsonResponse({'div_list':div_list})


def load_taluka(request):
	dist = request.GET.get('dist')
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	if dist.isdigit():
		div_list = list(Taluka.objects.filter(dist_id=dist).values('taluka_name'))
	else:
			div_list = list(Taluka.objects.filter(dist__district_name__iexact=dist).values('taluka_name'))
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	return JsonResponse({'div_list':div_list})


def load_village(request):
	taluka = request.GET.get('taluka')
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	if taluka.isdigit():
		div_list = list(Village.objects.filter(taluka_id=taluka).values('village_name'))
	else:
			div_list = list(Village.objects.filter(taluka__taluka_name__iexact=taluka).values('village_name'))
	# div_list = list(Range.objects.filter(id=range_area).values('division_id'))
	return JsonResponse({'div_list':div_list})

@group_permissions('role_permission_list')
def role_permission_list(request):
	# role_permission_list = RolePermission.objects.all()
	role_permission_list = RoleMethod.objects.filter().values()
	# role_list = Group.objects.values('name','id')
	# role_list = Group.objects.values('name')
	role_list = Group.objects.values('name','id').filter(is_delete=False)
	parent_data=[]
	parent_data=[]
	rlist=list(role_permission_list)
	for keys in rlist:
		if keys['parent_id'] is None:
			keys['childs']=[]
			parent_data.append(keys)

	for keys in rlist:
		for key in parent_data:
			if key['id'] == keys['parent_id']:
				key['childs'].append(keys)
	# role_permission_list =
	return render(request,"my_app/tigram/admin/all_permissions.html",{'role_list':role_list,'permissions1':list(role_permission_list),'permissions':parent_data,'menu':'permissions'})

@group_permissions('save_role_permission')
def save_role_permission(request):
	permissions_list = request.POST.getlist('perm_list[]')
	group_id = request.POST.get('group')
	role_perm=[]
	RolePermission.objects.filter(group_id=group_id).delete()
	for each in permissions_list:
		each_role_perm = RolePermission(method_id=each,group_id=group_id,created_by_id=request.user.id)
		role_perm.append(each_role_perm)
	RolePermission.objects.bulk_create(role_perm)
	return JsonResponse({'message':'Added successfully!'})

@group_permissions('view_role_permission')
def view_role_permission(request,role_id):
	# permissions_list = request.POST.getlist('perm_list[]')
	# group_id = request.POST.get('group')
	# role_perm=[]
	permissions = RolePermission.objects.filter(group_id=role_id).values_list('method_id',flat=True)
	# RolePermission.objects.filter(group_id=group_id).delete()
	# for each in permissions_list:
	# 	each_role_perm = RolePermission(method_id=each,group_id=group_id,created_by_id=request.user.id)
	# 	role_perm.append(each_role_perm)
	# RolePermission.objects.bulk_create(role_perm)
	return JsonResponse({'permissions':list(permissions)})
	# return render(request)

@group_permissions('edit_role_permission')
def edit_role_permission(request,role_id):
	# role_permission_list = RolePermission.objects.all()
	role_permission_list = RoleMethod.objects.all().values()
	parent_list = RoleMethod.objects.filter(types='parent').values('id')
	role_list = Group.objects.values('name','id')
	rlist=list(role_permission_list)
	parent_data=[]
	for keys in rlist:
		if keys['parent_id'] is None:
			keys['childs']=[]
			parent_data.append(keys)

	for keys in rlist:
		for key in parent_data:
			if key['id'] == keys['parent_id']:
				key['childs'].append(keys)
	# role_permission_list =
	return render(request,"my_app/tigram/admin/all_permissions.html",{'selected_role':role_id,'role_list':role_list,'parent_list':list(parent_list),'permissions2':role_permission_list,'permissions':parent_data,'menu':'permissions'})


@login_required
@group_required('admin')
def admin_dashboard(request):
	context={}
	context['active_users_no'] = CustomUser.objects.filter(groups__name__in=['user'],is_delete=False).count()
	context['application_no'] = Applicationform.objects.all().count()
	#context['application_no'] = CustomUser.objects.filter(groups__name__in=['user','deputy range officer','forest range officer','division officer','revenue officer'],is_delete=False).count()
	context['officer_no'] = CustomUser.objects.filter(groups__name__in=['deputy range officer','forest range officer','division officer','field officer','state officer'],is_delete=False).count()
	context['div_no'] = Division.objects.filter(is_delete=False).count()
	context['range_no'] = Range.objects.filter(is_delete=False).count()
	context['revenue_no'] = CustomUser.objects.filter(groups__name='revenue officer',is_delete=False).count()
	cs_user = CustomUser.objects.all().values_list('id',flat=True)
	cs_group = Group.objects.all().values_list('user',flat=True)


	context['no_of_app']=Applicationform.objects.all().count()
	context['no_of_tp'] = TransitPass.objects.all().count()
	context['no_of_tp_pending'] = Applicationform.objects.filter(Q(application_status='S')|Q(application_status='P')).count()
	context['no_of_tp_rejected'] = Applicationform.objects.filter(application_status='R').count()

	return render(request,"my_app/tigram/admin/dashboard.html",{'context':context,'menu':'dashboard'})

@login_required
@group_required('admin')
def Gis(request):

	return render(request,"my_app/tigram/admin/gis.html")

@login_required
@group_required('admin')
def ViewMap(request):

	return render(request,"my_app/tigram/admin/map_view_code.html")

@login_required
@group_required('admin')
def view_users(request):
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(is_delete=False,groups__name='user')
	all_users_list=CustomUser.objects.filter(is_delete=False,groups__name='user').values()
	return render(request,"my_app/tigram/admin/user_mange2.html",{'all_users':all_users,'proof_list':proof_list,'menu':'user','all_users_list':list(all_users_list)})

@login_required
@group_required('admin')
def update_users(request,user_id):
	cust_user = CustomUser.objects.filter(id=user_id)

	if cust_user:
		created_,ctx= update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)

	return JsonResponse({'message':'Updated Successfully!','response_code':'success'})


@login_required
@group_required('admin')
def delete_users(request):
	message=""
	if request.method =="POST":
		delete_list = request.POST.getlist('delete_list[]')
		# delete_list=delete_list.split(",")
		is_deleted= CustomUser.objects.filter(id__in=delete_list).update(is_delete=True)
		# is_deleted= CustomUser.objects.filter(id__in=delete_list).delete()
		if is_deleted:
			message = "All selected users deleted!"
			return JsonResponse({'message':message})
	message="No Action Occurred!"
	return JsonResponse({'message':message})

@login_required
@group_required('admin')
def detail_view_users(request,user_id):
	detail_user=list(CustomUser.objects.filter(id=user_id).values())
	return JsonResponse({'detail_user':detail_user})

@login_required
@group_required('admin')
def detail_view_officer(request,user_id,officer_type):
	rev_detail=[]
	detail_user=list(CustomUser.objects.filter(id=user_id).values())
	if officer_type =='revenue':
		rev_detail=list(RevenueOfficerdetail.objects.filter(Rev_user=user_id).values())
	elif officer_type == "division_officer":
		rev_detail=list(DivisionOfficerdetail.objects.filter(div_user=user_id).values())
	elif officer_type == 'fod' :
		rev_detail=list(ForestOfficerdetail.objects.filter(fod_user=user_id).values())
	elif officer_type == 'deputy':
		rev_detail=list(ForestOfficerdetail.objects.filter(fod_user=user_id).values())
	elif officer_type == 'field':
		rev_detail=list(ForestOfficerdetail.objects.filter(fod_user=user_id).values())
	elif officer_type == 'state':
		rev_detail=list(StateOfficerdetail.objects.filter(state_user_id=user_id).values())
	return JsonResponse({'detail_user':detail_user,'rev_detail':rev_detail})

@login_required
@group_required('admin')
def delete_user(request,user_id):
	# detail_user=CustomUser.objects.filter(id=user_id).delete()
	detail_user=CustomUser.objects.filter(id=user_id).update(is_delete=True)
	return JsonResponse({'message':"Successfully Deleted User"})
@login_required
@group_required('admin')
def view_deputy_officers(request):
 proof_list = PhotoProof.objects.all().values()
 all_users=CustomUser.objects.filter(is_delete=False,groups__name='deputy range officer')
 range_areas = Range.objects.filter(is_delete=False).values('name','id')
 div_list = Division.objects.filter(is_delete=False).values('name','id')
 checkpost = CheckPostsKerala.objects.all().values('name','id')
 return render(request,"my_app/tigram/admin/all_officer.html",{'all_users':all_users,
			'proof_list':proof_list,'menu':'deputy_officer',
			'range_areas':range_areas,'div_list':div_list,'checkpost':checkpost})


@login_required
@group_required('admin')
def add_revenue_officers(request):
	photo_proof_name = request.POST.get('photo_proof_select')
	photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='revenue officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	created_,ctx= create_new_user(request,'revenue officer')
	if ctx['response_code'] =="error":
		return JsonResponse(ctx)
	rev_user= RevenueOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		Rev_user=created_,
		range_name_id=range_name,
		division_name_id=division_name
		)
	return JsonResponse({'message':'Officer Created Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def add_forest_range_officers(request):
	photo_proof_name = request.POST.get('photo_proof_select')
	photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='forest range officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	created_,ctx= create_new_user(request,'forest range officer')
	if ctx['response_code'] =="error":
		return JsonResponse(ctx)

	rev_user= ForestOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		fod_user=created_,
		range_name_id=range_name,
		division_name_id=division_name
		)
	return JsonResponse({'message':'Officer Created Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def add_deputy_range_officers(request):
	photo_proof_name = request.POST.get('photo_proof_select')
	photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='deputy range officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	created_,ctx= create_new_user(request,'deputy range officer')
	if ctx['response_code'] =="error":
		return JsonResponse(ctx)

	rev_user= ForestOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		fod_user=created_,
		range_name_id=range_name,
		division_name_id=division_name
		)
	return JsonResponse({'message':'Officer Created Successfully!','response_code':'success'})

@login_required
@group_required('admin')
def view_division_officers(request):
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(is_delete=False,groups__name='division officer')
	div_list = Division.objects.filter(is_delete=False).values('name','id')
	return render(request,"my_app/tigram/admin/all_dfo.html",{'all_users':all_users,
				'proof_list':proof_list,'menu':'division_officer',
				'div_list':div_list})

def add_division_officers(request):
	photo_proof_name = request.POST.get('photo_proof_select')
	photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='division officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	created_,ctx= create_new_user(request,'division officer')
	if ctx['response_code'] =="error":
		return JsonResponse(ctx)

	rev_user= DivisionOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		div_user=created_,
		division_name_id=division_name
		)
	return JsonResponse({'message':'Officer Created Successfully!','response_code':"success"})

@login_required
@group_required('admin')
def update_division_officers(request,user_id):
	photo_proof_name = request.POST.get('photo_proof_select')
	#photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	# proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='division officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	if all_users:
		created_,ctx = update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)
		DivisionOfficerdetail.objects.filter(div_user_id=user_id).update(post=post_name,
			office_address=office_address,division_name_id=division_name)

	return JsonResponse({'message':'Updated Successfully!','response_code':"success"})

@login_required
@group_required('admin')
def view_field_officers(request):
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(is_delete=False,groups__name='field officer')
	range_areas = Range.objects.filter(is_delete=False).values('name','id')
	div_list = Division.objects.filter(is_delete=False).values('name','id')
	checkpost = CheckPostsKerala.objects.all().values('name','id')
	return render(request,"my_app/tigram/admin/all_officer.html",{'all_users':all_users,
				'proof_list':proof_list,'menu':'field_officer','range_areas':range_areas,
				'div_list':div_list,'checkpost':checkpost})
@login_required
@group_required('admin')
def view_check_post_officers(request):
 proof_list = PhotoProof.objects.all().values()
 all_users=CustomUser.objects.filter(is_delete=False,groups__name='checkpost officer')
 range_areas = Range.objects.filter(is_delete=False).values('name','id')
 checkpost = CheckPostsKerala.objects.all()
 checkposts = CheckPostsKerala.objects.all()
 divisions = checkposts.values_list('division', flat=True).distinct()
 ranges = checkposts.values_list('range', flat=True).distinct()
 circle = checkposts.values_list('circle', flat=True).distinct()
 
 
 return render(request,"my_app/tigram/admin/all_officer.html",{'all_users':all_users,
				'proof_list':proof_list,'menu':'check_officer','range_areas':ranges,
				'div_list':divisions,'checkpost':checkpost,'user':request.user.id})
@login_required
@group_required('admin')
def view_check_post(request):
 checkpost = CheckPostsKerala.objects.all()



 checkposts = CheckPostsKerala.objects.all()
 divisions = checkposts.values_list('division', flat=True).distinct()
 ranges = checkposts.values_list('range', flat=True).distinct()
 circle = checkposts.values_list('circle', flat=True).distinct()
 
 return render(request,"my_app/tigram/admin/add_checkpost.html",{
			'menu':'check_officer','range_areas':ranges,
			'div_list':divisions,'checkpost':checkpost,'circle':circle})

@login_required
@group_required('admin')
def add_field_officers(request):
	photo_proof_name = request.POST.get('photo_proof_select')
	photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='field officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	created_,ctx= create_new_user(request,'field officer')
	if ctx['response_code'] =="error":
		return JsonResponse(ctx)

	rev_user= ForestOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		fod_user=created_,
		range_name_id=range_name,
		division_name_id=division_name
		)
	return JsonResponse({'message':'Created Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def add_checkpost_officer(request):
 photo_proof_name = request.POST.get('photo_proof_select')
 photo_proof_doc = request.FILES.get('photo_proof')
 office_address = request.POST.get('off_address')
 post_name = request.POST.get('post_name')
 range_name = request.POST.get('range_name')
 division_name = request.POST.get('div_name')
 checkpost = request.POST.get('checkpost')
 proof_list = PhotoProof.objects.all().values()
 all_users=CustomUser.objects.filter(groups__name='checkpost officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
 created_,ctx= create_new_user(request,'checkpost officer')
 if ctx['response_code'] =="error":
  return JsonResponse(ctx)
 where = CheckPostsKerala.objects.get(id=checkpost)
 
 CheckPostOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		check_user=created_,
		checkpost=where)
 return JsonResponse({'message':'Created Successfully!','response_code':'success'})

@login_required
@group_required('admin')
def add_check_post(request):
 address = request.POST.get('address')
 checkpost_name = request.POST.get('checkpost_name')
 range_name = request.POST.get('area_range')
 division_name = request.POST.get('division')





 checkpost= CheckPostsKerala.objects.create(
		circle=address,
		name=checkpost_name,
		range=range_name,
		division=division_name
		)
 messages.error(request,"Checkpost Created Successfully!")
 return redirect('admin_dashboard')
@login_required
@group_required('admin')
def delete_checkpost(request,id):
  check = CheckPostsKerala.objects.get(id=id)
  check.delete()
  messages.error(request, "Checkpost Deleted Successfully")
  return redirect('admin_dashboard')

@login_required
@group_required('admin')
def update_checkpost(request,id):
 if request.POST:
  address = request.POST['address']
  checkpost_name = request.POST['checkpost_name']
  range_name = request.POST['area_range']
  division_name = request.POST['division']
  check = CheckPostsKerala.objects.filter(id=id)
  check.update(circle=address, name=checkpost_name, range=range_name, division=division_name)
  messages.error(request, "Checkpost Updated Successfully")
  return redirect('admin_dashboard')
 check = CheckPostsKerala.objects.get(id=id)
 checkposts = CheckPostsKerala.objects.all()
 divisions = checkposts.values_list('division', flat=True).distinct()
 ranges = checkposts.values_list('range', flat=True).distinct()
 circle = checkposts.values_list('circle', flat=True).distinct()
 return render(request,"my_app/tigram/admin/update_chekpost.html",{
     'range_areas':ranges,
			'div_list':divisions,'circle':circle,
				'menu':'check_officer',
				'checkpost':check})
@login_required
@group_required('admin')

def update_field_officers(request,user_id):
	photo_proof_name = request.POST.get('photo_proof_select')
	# photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	# proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='field officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	if all_users:
		# created_= update_users_fun(request,user_id)
		created_,ctx= update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)
		ForestOfficerdetail.objects.filter(fod_user_id=user_id).update(post=post_name,
			office_address=office_address,range_name_id=range_name,division_name_id=division_name)

	return JsonResponse({'message':'Updated Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def update_checkpost_officers(request,user_id):
 if request.POST:
  office_address = request.POST['off_address']
  post_name = request.POST['post_name']
  checkpost = request.POST['checkpost']
  checkpost = CheckPostsKerala.objects.get(id = checkpost)
  officers= CheckPostOfficerdetail.objects.filter(check_user=user_id)
  officers.update(
		post=post_name,
		office_address=office_address,
		checkpost=checkpost)
  user = CustomUser.objects.get(id = user_id)
  user.name = request.POST['uname']
  user.email = request.POST['email']
  user.phone = request.POST['number']
  user.address = request.POST['address']
  user.password = request.POST['psw']
  user.save()
  
  messages.error(request, "Checkpost Officer details Updated Successfully")
  return redirect('admin_dashboard')
 officer = CheckPostOfficerdetail.objects.get(check_user = user_id)
 checkpost = CheckPostsKerala.objects.get(id = officer.checkpost.id)
 checks = CheckPostsKerala.objects.all()
 user_details = CustomUser.objects.get(id = user_id)
 return render(request,"my_app/tigram/admin/update_chekpost_officer.html",{
     'checks':checks,
				'menu':'check_officer',
				'checkpost':checkpost, 'user_details':user_details})
@login_required
@group_required('admin')
def view_state_officers(request):
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(is_delete=False,groups__name='state officer')
	#range_areas = Range.objects.filter(is_delete=False).values('name','id')
	#div_list = Division.objects.filter(is_delete=False).values('name','id')
	return render(request,"my_app/tigram/admin/all_state.html",{'all_users':all_users,
				'proof_list':proof_list,'menu':'state_officer'})
@login_required
@group_required('admin')
def add_state_officers(request):

	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	state_name = request.POST.get('state_name')
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='state officer')

	created_,ctx= create_new_user(request,'state officer')
	if ctx['response_code'] =="error":
		return JsonResponse(ctx)

	rev_user= StateOfficerdetail.objects.create(
		post=post_name,
		office_address=office_address,
		state_user=created_,
		state_name=state_name,
		)
	return JsonResponse({'message':'Created Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def update_state_officers(request,user_id):
	photo_proof_name = request.POST.get('photo_proof_select')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	state_name = request.POST.get('state_name')
	# state_user_id = request.POST.get('state_id')
	proof_list = PhotoProof.objects.all().values()

	all_users=CustomUser.objects.filter(groups__name='state officer')

	if all_users:

		created_,ctx= update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)
		StateOfficerdetail.objects.filter(state_user_id=user_id).update(post=post_name,
			office_address=office_address, state_name = state_name )

	return JsonResponse({'message':'Updated Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def update_users_fun(request,user_id):
	proof_list = PhotoProof.objects.all().values()
	# all_users=CustomUser.objects.filter(groups__name='user')
	context={}
	username = request.POST.get('uname')
	email = request.POST.get('email')
	phone = request.POST.get('number')
	passwd = request.POST.get('psw')
	passwd2 = request.POST.get('psw2')
	address = request.POST.get('address')
	photo_proof_no = request.POST.get('photo_proof_no')
	photo_proof_name = request.POST.get('photo_proof_select')
	photo_proof_doc = request.FILES.get('photo_proof')

	make_id = str(user_id)+'r'
	url = '/static/media/upload/'

	if photo_proof_doc!=None:
		saved_photo=upload_product_image_file(make_id,photo_proof_doc,url,'PhotoProof')
		CustomUser.objects.filter(id=user_id).update(photo_proof_img=saved_photo)

	if passwd!=passwd2:
		context['response_code'] = 'error'
		context['message']="Passwords doesnt match!"

	if 'response_code' in context:
		return False,context

	else:
		if passwd!='':
			new_password = make_password(passwd)
			cust_query = CustomUser.objects.filter(id=user_id).update(
				name=username,photo_proof_no=photo_proof_no, password=new_password,
				photo_proof_name=photo_proof_name,address=address)
		else:
	# isuser.update(password=new_password)
			cust_query = CustomUser.objects.filter(id=user_id).update(
				name=username,photo_proof_no=photo_proof_no,
				photo_proof_name=photo_proof_name,address=address)

		context['response_code'] = 'success'
		context['message']="Updated successfully!"
		return True,context
	return True,context
@login_required
@group_required('admin')
def update_deputy_range_officers(request,user_id):
	photo_proof_name = request.POST.get('photo_proof_select')
	# photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	# proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='deputy range officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	if all_users:
		# created_= update_users_fun(request,user_id)
		created_,ctx= update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)
		ForestOfficerdetail.objects.filter(fod_user_id=user_id).update(post=post_name,
			office_address=office_address,range_name_id=range_name,division_name_id=division_name)

	return JsonResponse({'message':'Updated Successfully!','response_code':'success'})

@login_required
@group_required('admin')
def update_revenue_officers(request,user_id):
	photo_proof_name = request.POST.get('photo_proof_select')
	# photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	# proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='revenue officer')

	# revenue = RevenueOfficerdetail.objects.all().values()
	if all_users:
		created_,ctx= update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)
		RevenueOfficerdetail.objects.filter(Rev_user_id=user_id).update(post=post_name,
			office_address=office_address,range_name_id=range_name,division_name_id=division_name)

	return JsonResponse({'message':'Updated Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def update_forest_range_officers(request,user_id):
	photo_proof_name = request.POST.get('photo_proof_select')
	# photo_proof_doc = request.FILES.get('photo_proof')
	office_address = request.POST.get('off_address')
	post_name = request.POST.get('post_name')
	range_name = request.POST.get('range_name')
	division_name = request.POST.get('div_name')

	# proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(groups__name='forest range officer')
	# revenue = RevenueOfficerdetail.objects.all().values()
	if all_users:
		created_,ctx= update_users_fun(request,user_id)
		if ctx['response_code'] =="error":
			return JsonResponse(ctx)
		ForestOfficerdetail.objects.filter(fod_user_id=user_id).update(post=post_name,
			office_address=office_address,range_name_id=range_name,division_name_id=division_name)
	return JsonResponse({'message':'Updated Successfully!','response_code':'success'})
@login_required
@group_required('admin')
def view_revenue_officers(request):
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(is_delete=False,groups__name='revenue officer')
	revenue = RevenueOfficerdetail.objects.all().values()
	range_areas = Range.objects.filter(is_delete=False).values('name','id')
	div_list = Division.objects.filter(is_delete=False).values('name','id')
	checkpost = CheckPostsKerala.objects.all().values('name','id')
	return render(request,"my_app/tigram/admin/all_officer.html",{'all_users':all_users,
				'proof_list':proof_list,'revenue_list':revenue,'menu':'revenue_officer',
				'range_areas':range_areas,'div_list':div_list,'checkpost':checkpost})

@login_required
@group_required('admin')
def view_forest_officers(request):
	proof_list = PhotoProof.objects.all().values()
	all_users=CustomUser.objects.filter(is_delete=False,groups__name='forest range officer')
	range_areas = Range.objects.filter(is_delete=False).values('name','id')
	div_list = Division.objects.filter(is_delete=False).values('name','id')
	checkpost = CheckPostsKerala.objects.all().values('name','id')
	return render(request,"my_app/tigram/admin/all_officer.html",{'all_users':all_users,
				'proof_list':proof_list,'menu':'forest_officer',
				'range_areas':range_areas,'div_list':div_list,'checkpost':checkpost})
@login_required
@group_required('admin')
def add_division(request):
	# context={}
	division = request.POST.get('division')
	state= request.POST.get('state')
	state_name = State.objects.filter(id=state).values('name')
	ranges = Division.objects.create(name=division,state_id = state,created_by_id=request.user.id)
	# messages = "Division added successfully!"
	# context['menu']='forest_officer'
	return JsonResponse({'messages':"Division added successfully!",'response_code':'success'})
@login_required
@group_required('admin')
def view_divisions(request):
	# context={}
	ranges = Division.objects.filter(is_delete=False).values('name','id','state__name','state_id','created_date')
	state = State.objects.filter(is_delete=False).values('name','id')
	# context['ranges'] = list(ranges)
	# return JsonResponse(context)
	return render(request,"my_app/tigram/admin/all_divisions.html",{'ranges':list(ranges),'menu':'divisions','state':list(state)})
@login_required
@group_required('admin')
def edit_division(request,div_id):

	div_name = request.POST.get('division')
	state = request.POST.get('state')
	ranges = Division.objects.all().values()
	Division.objects.filter(id=div_id).update(name=div_name,state_id =state)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Division updated successfully!",'response_code':'success'})
@login_required
@group_required('admin')
def delete_division(request,div_id):

	div_name = request.POST.get('div_name')
	Division.objects.filter(id=div_id).filter(is_delete=True)
	Division.objects.filter(id=div_id).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Division deleted successfully!"})
@login_required
@group_required('admin')
def delete_divisions(request):
	delete_list = request.POST.getlist('delete_list[]')
	# div_name = request.POST.get('div_name')
	Division.objects.filter(id__in=delete_list).update(is_delete=True)
	Range.objects.filter(division_id__in=delete_list).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Selected Divisions have been deleted successfully!"})

@login_required
@group_required('admin')
def view_tree_species(request):
	# context={}
	ranges = TreeSpecies.objects.filter(is_delete=False).values()
	# context['ranges'] = list(ranges)
	# return JsonResponse(context)
	return render(request,"my_app/tigram/admin/all_species.html",{'ranges':list(ranges),'menu':'species'})

@login_required
@group_required('admin')
def add_tree_species(request):
	# context={}
	species_name = request.POST.get('species_name')
	is_noc = True if request.POST.get('is_noc').lower() == 'true' else False
	ranges = TreeSpecies.objects.create(name=species_name,created_by_id=request.user.id,is_noc=is_noc)
	# messages = "Division added successfully!"
	# context['menu']='forest_officer'
	return JsonResponse({'messages':"Tree Species added successfully!",'response_code':'success'})

@login_required
@group_required('admin')
def edit_tree_species(request,speci_id):

	species_name = request.POST.get('species_name')
	is_noc = True if request.POST.get('is_noc') == 'true' else False
	ranges = TreeSpecies.objects.all().values()
	TreeSpecies.objects.filter(id=speci_id).update(name=species_name,is_noc=is_noc)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Species updated successfully!",'response_code':'success'})

@login_required
@group_required('admin')
def delete_tree_speci(request,speci_id):

	species_name = request.POST.get('species_name')
	TreeSpecies.objects.filter(id=speci_id).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Species deleted successfully!"})

@login_required
@group_required('admin')
def delete_tree_species(request):
	delete_list = request.POST.getlist('delete_list[]')
	# div_name = request.POST.get('div_name')
	TreeSpecies.objects.filter(id__in=delete_list).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Selected Species have been deleted successfully!"})

@login_required
@group_required('admin')
def add_range(request):
	# context={}
	range_name = request.POST.get('range_name')
	div_name = request.POST.get('div_name')
	ranges = Range.objects.create(name=range_name,division_id=div_name,created_by=request.user)
	return JsonResponse({'messages':"Range added successfully!",'response_code':'success'})
@login_required
@group_required('admin')
def edit_range(request,range_id):
	range_name = request.POST.get('range_name')
	div_name = request.POST.get('div_name')
	# ranges = Range.objects.create(name=range_name,division_id=div_name,created_by=request.user)
	Range.objects.filter(id=range_id).update(name=range_name,division_id=div_name)
	return JsonResponse({'messages':"Range updated successfully!",'response_code':'success'})

@login_required
@group_required('admin')
def delete_range(request,range_id):

	Range.objects.filter(id=range_id).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Range deleted successfully!"})
@login_required
@group_required('admin')
def delete_ranges(request):
	delete_list = request.POST.getlist('delete_list[]')
	# div_name = request.POST.get('div_name')
	Range.objects.filter(id__in=delete_list).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Selected Ranges have been deleted successfully!"})
@login_required
@group_required('admin')
def view_ranges(request):

	divisions = Division.objects.filter(is_delete=False).values()
	ranges = Range.objects.filter(is_delete=False)
	# context['ranges'] = list(ranges)
	# return JsonResponse(context)
	return render(request,"my_app/tigram/admin/all_ranges.html",{'ranges':ranges,'divisions':list(divisions),'menu':'ranges'})

@login_required
@group_required('admin')
def roles_list(request):
	# roles_list
	groups_list = Group.objects.filter(is_delete=False).exclude(name='admin').values()
	imp_groups_list = [2,3,4,5,6,7,18,19]
	return render(request,'my_app/tigram/admin/all_roles.html',{'roles_list':list(groups_list),'imp_groups_list':imp_groups_list,'menu':'roles'})
@login_required
@group_required('admin')
def add_role(request):
	# context={}
	grp_name = request.POST.get('grp_name')
	if grp_name is not None or grp_name != "":
		grp_name=grp_name.strip()
	count_ = Group.objects.all().count()
	ranges = Group.objects.get_or_create(id=count_+1,name=grp_name)
	return JsonResponse({'messages':"Role added successfully!",'response_code':'success'})
@login_required
@group_required('admin')
def edit_role(request,grp_id):
	# context={}
	grp_name = request.POST.get('grp_name')
	if grp_name is not None or grp_name != "":
		grp_name=grp_name.strip()
	ranges = Group.objects.filter(id=grp_id).update(name=grp_name)
	return JsonResponse({'messages':"Role updated successfully!",'response_code':'success'})
@login_required
@group_required('admin')
def delete_role(request,role_id):
	imp_groups_list = [2,3,4,5,6,7]
	if role_id not in imp_groups_list:
		Group.objects.filter(id=role_id).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Role deleted successfully!"})
@login_required
@group_required('admin')
def delete_roles(request):
	delete_list = request.POST.getlist('delete_list[]')
	# div_name = request.POST.get('div_name')
	# imp_groups_list = [2,3,4,5,6,7]
	# if role_id not in imp_groups_list:
	Group.objects.filter(id__in=delete_list).update(is_delete=True)
	# messages = "Division updated successfully!"
	return JsonResponse({'messages':"Selected Roles have been deleted successfully!"})
@login_required
@group_required('admin')
def admin_password(request):
	pass1=request.POST.get('pass1')
	pass2=request.POST.get('pass2')
	if pass1 != pass2:
		return JsonResponse({'messages':"Password doesn't match!"})
	passwd = make_password(pass1)
	CustomUser.objects.filter(id=request.user.id).update(password=passwd)
	return JsonResponse({'messages':'Password Updated Successfully!'})
@login_required
@group_required('admin')
def admin_vpassword(request):
	return render(request,'my_app/tigram/admin/adminchange_password.html',{'menu':'password'})

@login_required

@group_permissions('summary_report')
def summary_report(request):
	# logo1=settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
	logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
	logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
	logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
  #logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
	# pdf = pdfkit.from_string(wt, False,configuration=config)
	template = get_template("pdf_template/newsummaryreport.html")
	# css = os.path.join(settings.STATIC_URL, 'css/summaryreport.css', 'summaryreport.css')
	applications = Applicationform.objects.all().order_by('-id')

	if applications:
		context = {'applications':applications,"logo1":logo1,"logo2":logo2,"logo3":logo3}  # data is the context data that is sent to the html file to render the output.
		html = template.render(context)  # Renders the template with the context data.
		# pdf = pdfkit.from_string(html, False, configuration=config)
		# pdf = open("summaryreport.pdf")
		response = HttpResponse(content_type='application/pdf')
		# response['Content-Disposition'] = 'attachment; filename="Summary Report.pdf"'
		today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
		filename= 'SummaryReport-'+today_stamp+''
		response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'
		# find the template and render it.
		# template = get_template('pdf_template/transitpass.html')
		html = template.render(context)

		# create a pdf
		pisa_status = pisa.CreatePDF(
			html, dest=response, link_callback=link_callback)
		# if error then show some funy view
		if pisa_status.err:
			return HttpResponse('We had some errors <pre>' + html + '</pre>')
		return response
		# pdf.close()
		# os.remove("summaryreport.pdf")  # remove the locally created pdf file.
		return response
	else:
		# message = "No Data Found"
		return HttpResponseRedirect(reverse('officer_dashboard'))
		# return message

@login_required
@group_required('admin')
def query(request):
	context={}
	context['groups']=request.user.groups.values_list('name',flat = True)
	return render(request,"my_app/tigram/query.html",context)

def send_msg_otp_signup_verification(phone,name,otp):
    user_id = 0
    # send_status = 'pending'
    # message="not send"
    # name =""
    # phone=""
    # otp=""
    account_sid = settings.TWILIO_ACCOUNT_SID
    auth_token = settings.TWILIO_AUTH_TOKEN
    number = settings.TWILIO_NUMBER
    client = Client(account_sid, auth_token)
    name = name
    phone = phone
    otp =otp
    send_status = 'sent'
    message = "sent"
    # otp = "0000"
    # body = "Hi "+str(name)+",Your one time password for Tree Tribe account verification code is "+str(otp)
    # client = Client(account_sid, auth_token)
    # if is_valid_number(phone)==True:
    #     try:
    #         resp = client.messages.create(
    #                                       body=body,
    #                                       from_=number,
    #                                    to=phone)
    #         if resp.status =="queued":
    #             send_status = 'sent'
    #             message = "sent"
    #         elif resp.status =="sent":
    #             send_status = 'sent'
    #             message = "sent"

    #         elif resp.status =="pending":
    #             send_status = 'sent'
    #             message = "sent"
    #         elif resp.status_code =="400":
    #             send_status = 'Not sent'
    #             message = "Not sent"
    #             random_otp =0

    #         else:
    #             send_status = 'Not sent'
    #             message = "Not sent"
    #             random_otp =0
    #     except Exception as ex:
    #         import sys,os
    #         exc_type, exc_obj, exc_tb = sys.exc_info()
    #         fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    #         send_status = 'Error'
    #         message="Not send"

    # else:
    #     message = "Not sent"
    #     random_otp =0


    return message,send_status,otp

def forgot_password_email(email,name,otp):
    subject = 'OTP Verification email from TreeTribe  for Password Change'
    message = ' Hi'+str(name)+' , Please Find Your Otp:'+str(otp)+' For Password Change'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    status = send_mail( subject, message, email_from, recipient_list )
    return status


def generate_random_number():
    return random.randint(100000, 999999)
def otp_verification(request):
 context = {}
 mobile = request.POST.get('phone')
 email = request.POST.get('username')
 data=CustomUser.objects.filter(email=email,phone=mobile)
 if data:
     current_time =datetime.datetime.now()
     otp = new_otp_generateOTP()
     CustomUser.objects.filter(email=email, phone=mobile).update(forgot_code=otp,no_of_attempts_forgot='0',forgot_otp_created_at=current_time)
     USERNAME = "KERALAFOREST-KFDSER"
     PASSWORD = "Fmis@2021"
     SENDERID = "KFDSER"
     KEY = "98a52a38-b8fe-42c8-8fa7-60ba10fc5cbc"
     content = "KeralaForestDept - OTP for resetting your password for "+str(email)+" is "+str(otp)+"."
    
     templateid = "1407169907490040278"
     key = KEY
     message = "KeralaForestDept - OTP for resetting your password for "+"account"+str(email)+" is "+str(otp)+"."
     if otp_check_brute(mobile) == False:
      message = "Exceded Daily Limit !"
      return render(request, "my_app/tigram/forgotpassword.html",{"message":message})
     sendSingleSMS_new(USERNAME, PASSWORD, SENDERID, message, mobile, templateid, key)
     return render(request, "my_app/tigram/otpverification.html",{"phone":mobile})

 message = "Please try again or Please verify your registered email or phone number with admin"
 return render(request, "my_app/tigram/forgotpassword.html",{"message":message})



def forgot_password(request):
	context = {}
	message = ""
	if request.method == 'POST':
		email = request.POST.get('email')

		if email !="":
			email = request.POST.get('email')
			user_exists = CustomUser.objects.filter(email=email)

			if user_exists:
				otp ="0000"
				# otp = "".join(random.sample("0123456789", 4))
                # status = forgot_password_email(user_exists[0].email,user_exists[0].name,otp)
				otp_chk = SendOtp.objects.filter(otp_owner_id=user_exists[0].id)
				if otp_chk:

					otp1 = SendOtp.objects.filter(otp_owner_id=user_exists[0].id).update(otp=otp,otp_verified=False)
				else:

					otp1 = SendOtp(otp_owner_id=user_exists[0].id,otp=otp)
					otp1.save()

				context["email"] = email
				return render(request,"my_app/tigram/otpverification.html",{"email":email})

			else:
				message="Invalid Email"
				return render(request,"my_app/tigram/forgotpassword.html",{"message":message})

		else:
			phone = request.POST.get('phone')
			user_exists = CustomUser.objects.filter(phone=phone)
			otp ="0000"
			if user_exists:
				otp_chk = SendOtp.objects.filter(otp_owner_id=user_exists[0].id)
				if otp_chk:
				# otp = "".join(random.sample("0123456789", 4))
					otp ="0000"
					# message,send_status,random_otp=send_msg_otp_signup_verification(user_exists[0].phone,user_exists[0].name,otp)

					otp1 = SendOtp.objects.filter(otp_owner_id=user_exists[0].id).update(otp=otp,otp_verified=False)
				else:
					otp ="0000"
					# otp = "".join(random.sample("0123456789", 4))
					# message,send_status,random_otp=send_msg_otp_signup_verification(user_exists[0].phone,user_exists[0].name,otp)

					otp1 = SendOtp(otp_owner_id=user_exists[0].id,otp=otp)
					otp1.save()


				email = phone
				# context["email"] = "email"
				return render(request,"my_app/tigram/otpverification.html",{"email":email})

			else:
				message="Invalid Phone Number"

				return render(request,"my_app/tigram/forgotpassword.html",{"message":message})



		# chkemail = CustomUser.objects.filter(email__iexact=email)
		# if chkemail:
		# context["email"] = "email"
		# return render(request,"my_app/tigram/otpverification.html",context)
		# else:
		# 	context["error"] = "Email id not Registered."
		# 	return render(request,"my_app/tigram/forgotpassword.html",context)


	# application_detail = Applicationform.objects.filter(id=app_id).update(reason_range_officer=reason)

	return render(request,"my_app/tigram/forgotpassword.html")


def Otp_verify(request):

	if request.method == 'POST':
		phone = request.POST.get('phone')
		otp = request.POST.get('otp')
		user_Exist = CustomUser.objects.filter(phone=phone,forgot_code=otp)
		if user_Exist:
			data = CustomUser.objects.get(phone=phone, forgot_code=otp)
			db_time = data.forgot_otp_created_at
			datetime_obj = datetime.strptime(db_time,'%Y-%m-%d %H:%M:%S.%f')
			now = datetime.now()
			time_difference = now - datetime_obj
			if time_difference > timedelta(minutes=3):
				message = "OTP expired"
				return render(request, "my_app/tigram/forgotpassword.html", {"phone": phone, "message": message})
			else:
				return render(request, "my_app/tigram/newpassword.html", {"phone": phone})
		else:
			user_Existt = CustomUser.objects.get(phone=phone)
			attempts =user_Existt.no_of_attempts_forgot
			val=int(attempts)
			val=val+1
			CustomUser.objects.filter(phone=phone).update(no_of_attempts_forgot=val)
			if val > 3:
				message = "You execeded the limit please try after sometime"
				return render(request, "my_app/tigram/forgotpassword.html",{"temp": "Wrong otp entered.", "phone": phone, "message": message})
			else:
				message = "Invalid OPT"
				return render(request, "my_app/tigram/otpverification.html",{"temp": "Wrong otp entered.", "phone": phone, "message": message})

	return render(request,"my_app/tigram/otpverification.html")


def set_newpassword(request):

	if request.method == 'POST':
		# if 'user' in request :
		# user=request.user.id
		passwd = request.POST.get('npass')
		passwd1 = request.POST.get('rpass')
		phone = request.POST.get('phone')
		isuser = CustomUser.objects.filter(phone=phone)
		if passwd == passwd1:
			if isuser:
			# isuser.set_password(passwd)
				new_password = make_password(passwd)
				isuser.update(password=new_password)
				message = "Password Changed Successfully"
				return render(request,"my_app/tigram/ulogin.html",{'message':message})

		else:
			message="Password not changed"
			return render(request,"my_app/tigram/ulogin.html",{'message':message})
		# email = request.POST.get('email')
		# context["email"] = email
		#------ return render(request,"my_app/tigram/ulogin.html")
	# reason = request.POST.get('reason')
	# application_detail = Applicationform.objects.filter(id=app_id).update(reason_range_officer=reason)

	return render(request,"my_app/tigram/newpassword.html")














from django.db.models import Count
from .serializers import*
from datetime import timedelta
from django.core import serializers
@login_required(login_url='staff_login')

@group_permissions('reject_reason')
def reject_reason(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	app_list = Applicationform.objects.filter(application_status='R')
	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		#ajax procedure
		app_list=app_list.values('disapproved_reason')
		len_aplist = len(app_list)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
		dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist
								 for reject_type in app_list.annotate(Count('disapproved_reason')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		len_aplist = len(app_list)
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['dict_of_percentages']=dict_of_percentages
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		app_list=app_list.values('reason_office','reason_range_officer','reason_depty_ranger_office','disapproved_reason')
		len_aplist = len(app_list)

		dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist
								 for reject_type in app_list.annotate(Count('disapproved_reason')) }
		context['dict_of_percentages'] =dict_of_percentages
		context['app_list'] = list(app_list)
		early_date = Applicationform.objects.earliest('created_date')
		# d=datetime.strptime(early_date.created_date)
		context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# context['early_date'] =d.strftime('%Y-%m-%d')
		# context['early_date'] =
		context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		context['to_date']=to_date
		context['from_date']=from_date
		context['select_mon']=select_mon
	return render(request,'my_app/tigram/app_rejection.html',context)



@group_permissions('reject_reason1')
def reject_reason1(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	app_list = Applicationform.objects.filter(application_status='R')
	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		#ajax procedure
		app_list=app_list.values('disapproved_reason')
		len_aplist = len(app_list)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
		dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist
								 for reject_type in app_list.annotate(Count('disapproved_reason')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		len_aplist = len(app_list)
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['dict_of_percentages']=dict_of_percentages
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		app_list=app_list.values('reason_office','reason_range_officer','reason_depty_ranger_office','disapproved_reason')
		len_aplist = len(app_list)

		dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist
								 for reject_type in app_list.annotate(Count('disapproved_reason')) }
		context['dict_of_percentages'] =dict_of_percentages
		context['app_list'] = list(app_list)
		early_date = Applicationform.objects.earliest('created_date')
		# d=datetime.strptime(early_date.created_date)
		context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# context['early_date'] =d.strftime('%Y-%m-%d')
		# context['early_date'] =
		context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		context['to_date']=to_date
		context['from_date']=from_date
		context['select_mon']=select_mon
	return render(request,'my_app/tigram/app_rejection.html',context)



from django.db.models import Count, Case,Sum, When, CharField,IntegerField,DecimalField,FloatField, F
@login_required(login_url='staff_login')

@group_permissions('no_of_applicantions')
def no_of_applicantions(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	# app_list = Applicationform.objects.values(
 #    'created_date'
	# ).annotate(
	#     no_of_received=Count('pk')
	# ).annotate(
	#     no_of_approved=Count(Case(
	#     	When(application_status='A',then=F('id')),
	#     	output_field=IntegerField(),))
	# ).annotate(
	#     no_of_rejected=Count(Case(
	#     	When(application_status='R',then=F('id')),
	#     	output_field=IntegerField(),))
	# ).order_by('created_date')
	range_name = request.GET.get('range_name',None)
	village_type = request.GET.get('village_type',None)
	app_list = Applicationform.objects.filter(is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(division__icontains=div_name[0].division_name.name)
	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(is_form_two=village_type)
		total_approved_applicant=app_list.filter(application_status='A').count()
		total_rejected_applicant=app_list.filter(application_status='R').count()
		app_list=app_list.values(
		'created_date'
		).annotate(
		no_of_received=Count('pk')
		).annotate(
		no_of_approved=Count(Case(
			When(application_status='A',then=F('id')),
			output_field=IntegerField(),))
		).annotate(
		no_of_rejected=Count(Case(
			When(application_status='R',then=F('id')),
			output_field=IntegerField(),))
		).order_by('created_date')
		#ajax procedure
		# app_list=app_list.values('reason_office')
		len_aplist = len(app_list)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['applicantions']=list(app_list)
		context['total_rejected_applicant']=total_rejected_applicant
		context['total_approved_applicant']=total_approved_applicant
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		app_list=app_list.values('reason_office','reason_range_officer','reason_depty_ranger_office')
		len_aplist = len(app_list)

		dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
								 for reject_type in app_list.annotate(Count('reason_office')) }
		context['dict_of_percentages'] =dict_of_percentages
		context['app_list'] = list(app_list)
		early_date = Applicationform.objects.earliest('created_date')
		# d=datetime.strptime(early_date.created_date)
		context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# context['early_date'] =d.strftime('%Y-%m-%d')
		# context['early_date'] =
		context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		context['to_date']=to_date
		context['from_date']=from_date
		context['select_mon']=select_mon
	return render(request,'my_app/tigram/tabel_01.html',context)



@group_permissions('no_of_applicantions1')
def no_of_applicantions1(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	range_name = request.GET.get('range_name',None)
	village_type = request.GET.get('village_type',None)
	if range_name:
		app_list = Applicationform.objects.filter(is_noc=False,area_range=range_name)
	else:
		app_list = Applicationform.objects.filter(is_noc=False)
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		# if select_mon !='' and select_mon !=  None and village_type =="True" or village_type=="False":
		# 	app_list = app_list.filter(created_date__gte=six_month_previous_date,is_form_two=village_type,area_range=range_name)

		if village_type =="both"or village_type==None  :
			pass

		else:

			app_list = Applicationform.objects.filter(is_form_two=village_type,area_range=range_name)
			app_list=app_list.all()
		total_approved_applicant=app_list.filter(application_status='A').count()
		total_rejected_applicant=app_list.filter(application_status='R').count()
		app_list=app_list.values(
		'created_date'
		).annotate(
		no_of_received=Count('pk')
		).annotate(

		no_of_approved=Count(Case(
			When(application_status='A',then=F('id')),
			output_field=IntegerField(),))
		).annotate(
		no_of_rejected=Count(Case(
			When(application_status='R',then=F('id')),
			output_field=IntegerField(),))
		).order_by('created_date')

		context['applicantions']=list(app_list)
		context['total_rejected_applicant']=total_rejected_applicant
		context['total_approved_applicant']=total_approved_applicant
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:

		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		app_list=app_list.values('reason_office','reason_range_officer','reason_depty_ranger_office')
		len_aplist = len(app_list)

		dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
								 for reject_type in app_list.annotate(Count('reason_office')) }
		context['dict_of_percentages'] =dict_of_percentages
		context['app_list'] = list(app_list)
		early_date = Applicationform.objects.earliest('created_date')
		# d=datetime.strptime(early_date.created_date)
		context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# context['early_date'] =d.strftime('%Y-%m-%d')
		# context['early_date'] =
		context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		context['to_date']=to_date
		context['from_date']=from_date
		context['select_mon']=select_mon
	return render(request,'my_app/tigram/tabel_01.html',context)



from django.db.models.functions import Cast
@group_permissions('species_wise_transport')
def species_wise_transport(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	sel_sp = request.GET.get('sel_sp')

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	applications_list=Applicationform.objects.filter(is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
		# applications_list=applications_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# 	applications_list=applications_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		# 	applications_list=applications_list.filter(area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
			applications_list= applications_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
				applications_list= applications_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
				applications_list= applications_list.filter(created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('species_of_tree',
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		 total_no_of_trees=Count('id')
		).annotate(
		volume_sum=Sum('volume')
		)
		len_aplist = len(app_list)
		applications_list = applications_list.values('created_date').order_by('-created_date').annotate(
			as_float=Cast('total_trees', IntegerField())
			).annotate(
			total_trees=Sum('as_float'),
			)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['applicantions']=list(app_list)
		context['applications_list']=list(applications_list)
		#context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

		# context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# # context['early_date'] =d.strftime('%Y-%m-%d')
		# # context['early_date'] =
		# context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		# context['to_date']=to_date
		# context['from_date']=from_date
		# context['select_mon']=select_mon
	return render(request,'my_app/tigram/tabel_01.html',context)


from django.db.models.functions import Cast
@group_permissions('species_wise_transport_admin')
def species_wise_transport_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	sel_sp = request.GET.get('sel_sp')
	# app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	applications_list=Applicationform.objects.filter(is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
		# applications_list=applications_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# 	applications_list=applications_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		# 	applications_list=applications_list.filter(area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list = app_list.filter(appform__created_date__gte=six_month_previous_date)
			applications_list = applications_list.filter(created_date__gte=six_month_previous_date)
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
			applications_list= applications_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
				applications_list= applications_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
				applications_list= applications_list.filter(created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('species_of_tree',
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		 total_no_of_trees=Count('id')
		).annotate(
		volume_sum=Sum('volume')
		)
		len_aplist = len(app_list)
		applications_list = applications_list.values('created_date').order_by('-created_date').annotate(
			as_float=Cast('total_trees', IntegerField())
			).annotate(
			total_trees=Sum('as_float'),
			)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['applicantions']=list(app_list)
		context['applications_list']=list(applications_list)
		#context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		# context['group'] = list(groups)

		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

		# context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# # context['early_date'] =d.strftime('%Y-%m-%d')
		# # context['early_date'] =
		# context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		# context['to_date']=to_date
		# context['from_date']=from_date
		# context['select_mon']=select_mon
	return render(request,'my_app/tigram/tabel_01.html',context)


@group_permissions('species_wise_dest_transport')
def species_wise_dest_transport(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	sel_sp = request.GET.get('sel_sp')

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	#applications_list=Applicationform.objects.filter(is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
		#applications_list=applications_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# 	applications_list=applications_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		# 	applications_list=applications_list.filter(area_range__icontains=range_name)

		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

		#applications_list=applications_list.filter(division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('species_of_tree','appform__destination_details',
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		volume_sum=Sum('volume')
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		#context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)

@group_permissions('species_wise_dest_transport_admin')
def species_wise_dest_transport_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	sel_sp = request.GET.get('sel_sp')
	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	#applications_list=Applicationform.objects.filter(is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
		#applications_list=applications_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# 	applications_list=applications_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		# 	applications_list=applications_list.filter(area_range__icontains=range_name)

		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

		#applications_list=applications_list.filter(division__icontains=div_name[0].division_name.name)


	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('species_of_tree','appform__destination_details',
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		volume_sum=Sum('volume')
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		#context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		# context['group'] = list(groups)

		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)

@group_permissions('trees_transport')
def trees_transport(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values(
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		volume_sum=Sum('volume')
		)
		len_aplist = len(app_list)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

		# context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# # context['early_date'] =d.strftime('%Y-%m-%d')
		# # context['early_date'] =
		# context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		# context['to_date']=to_date
		# context['from_date']=from_date
		# context['select_mon']=select_mon
	return render(request,'my_app/tigram/tabel_01.html',context)


@group_permissions('trees_transport_admin')
def trees_transport_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values(
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		volume_sum=Sum('volume')
		)
		len_aplist = len(app_list)
		# dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
  #                                             for reject_type in app_list.annotate(Count('reason_office')) }
        # d_dict_of_percentages = { reject_type['reason_office']:reject_type['reason_office__count'] * 100/len_aplist
        #                                       for reject_type in app_list.annotate(Count('reason_office')) }
		# reject_serializer=RejectApplicationSerializer(app_list,many=True)
		# s_data=serializers.serialize('json', app_list)
		# context['app_list'] = list(app_list) #reject_serializer.data#
		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

		# context['early_date'] = datetime.strftime(early_date.created_date, '%Y-%m-%d')
		# # context['early_date'] =d.strftime('%Y-%m-%d')
		# # context['early_date'] =
		# context['today'] = datetime.strftime(datetime.today(),'%Y-%m-%d')
		# context['to_date']=to_date
		# context['from_date']=from_date
		# context['select_mon']=select_mon
	return render(request,'my_app/tigram/tabel_01.html',context)

@group_permissions('total_volume_dest')
def total_volume_dest(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		totalvolume=app_list.aggregate(Sum('volume'))
		app_list=app_list.values('appform__destination_details',
		'appform__created_date').annotate(
		volume_sum=Sum('volume')
		).annotate(
		volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
		# output_field=format('volume_percentage', ".2f"),
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)


@group_permissions('total_volume_dest_admin')
def total_volume_dest_admin(request, objects_filter=ForestOfficerdetail.objects.all()):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = objects_filter
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		totalvolume=app_list.aggregate(Sum('volume'))
		app_list=app_list.values('appform__destination_details',
		'appform__created_date').annotate(
		volume_sum=Sum('volume')
		).annotate(
		volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
		# output_field=format('volume_percentage', ".2f"),
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)


from django.db.models.functions import ExtractDay

@group_permissions('approval_time_report')
def approval_time_report(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	app_list = Applicationform.objects.filter(application_status='A',is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values(
		'created_date').annotate(
		no_of_applicantions=Count('id')
		).annotate(
		applications_percentage=F('no_of_applicantions')*100/totalapp,
		# output_field=format('volume_percentage', ".2f"),
		).annotate(
		time_taken_applications=ExtractDay(F('transit_pass_created_date')-F('created_date')),
		# output_field=time_taken_applications.strftime('%j'),
		).order_by('created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)


@group_permissions('approval_time_report_admin')
def approval_time_report_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	app_list = Applicationform.objects.filter(application_status='A',is_noc=False)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(division__icontains=div_name[0].division_name.name)

	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values(
		'created_date').annotate(
		no_of_applicantions=Count('id')
		).annotate(
		applications_percentage=F('no_of_applicantions')*100/totalapp,
		# output_field=format('volume_percentage', ".2f"),
		).annotate(
		time_taken_applications=ExtractDay(F('transit_pass_created_date')-F('created_date')),
		# output_field=time_taken_applications.strftime('%j'),
		).order_by('created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)


@group_permissions('cutting_reasons_report')
def cutting_reasons_report(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Applicationform.objects.filter(is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(division__icontains=div_name[0].division_name.name)

	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values(
		'created_date','purpose').annotate(
		no_of_applicantions=Count('id')
		).annotate(
		applications_percentage=F('no_of_applicantions')*100/totalapp,
		# output_field=format('volume_percentage', ".2f"),
		).order_by('created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)

@group_permissions('cutting_reasons_report')
def cutting_reasons_report_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Applicationform.objects.filter(is_noc=False)
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(division__icontains=div_name[0].division_name.name)

	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(is_form_two=village_type)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values(
		'created_date','purpose').annotate(
		no_of_applicantions=Count('id')
		).annotate(
		applications_percentage=F('no_of_applicantions')*100/totalapp,
		# output_field=format('volume_percentage', ".2f"),
		).order_by('created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)


@group_permissions('trees_cutted_report')
def trees_cutted_report(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	sel_sp = request.GET.get('sel_sp')
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		# else:

		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values('species_of_tree',
		'appform__created_date').annotate(
		no_of_applicantions=Count('appform__id')
		).annotate(
		no_after_cutting=Count(Case(
    	When(appform__trees_cutted=True,then=F('appform__id')),
    	output_field=IntegerField(),)),
		).annotate(
		no_before_cutting=Count(Case(
    	When(appform__trees_cutted=False,then=F('appform__id')),
    	output_field=IntegerField(),)),
		).annotate(
		after_cutting_percentage=F('no_after_cutting')*100/F('no_of_applicantions'),
		# output_field=format('volume_percentage', ".2f"),
		).annotate(
		before_cutting_percentage=F('no_before_cutting')*100/F('no_of_applicantions'),
		# output_field=format('volume_percentage', ".2f"),
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# trees=load_tree_species()

		trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
		context['trees_species'] = list(trees_species_list)
		# context['trees_species_length']=len(context['trees_species'])
		context['len_aplist']=len_aplist
		# context['trees']=list(trees)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

		return render(request,'my_app/tigram/tabel_01.html',context)

@group_permissions('trees_cutted_report_admin')
def trees_cutted_report_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
	sel_sp = request.GET.get('sel_sp')
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		# if range_name=="" or range_name == None :
		# 	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
		# 	app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		# else:
		# 	app_list = app_list.filter(appform__area_range__icontains=range_name)
		div_name1 = request.GET.get('div_name',None)
		div_name=""
		if range_name=="" or range_name == None :
			pass
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
		# if groups[0] not in ['state officer']:
		if groups[0] in ['state officer']:
				if div_name1=="" or div_name1 == None :
					# div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
					pass
				else:
					app_list = app_list.filter(appform__division__iexact=div_name1)
		else:
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		village_type = request.GET.get('village_type',None)
		if village_type =="both"or village_type==None :
			pass
		else:
			app_list=app_list.filter(appform__is_form_two=village_type)
		# else:

		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values('species_of_tree',
		'appform__created_date').annotate(
		no_of_applicantions=Count('appform__id')
		).annotate(
		no_after_cutting=Count(Case(
    	When(appform__trees_cutted=True,then=F('appform__id')),
    	output_field=IntegerField(),)),
		).annotate(
		no_before_cutting=Count(Case(
    	When(appform__trees_cutted=False,then=F('appform__id')),
    	output_field=IntegerField(),)),
		).annotate(
		after_cutting_percentage=F('no_after_cutting')*100/F('no_of_applicantions'),
		# output_field=format('volume_percentage', ".2f"),
		).annotate(
		before_cutting_percentage=F('no_before_cutting')*100/F('no_of_applicantions'),
		# output_field=format('volume_percentage', ".2f"),
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# trees=load_tree_species()

		trees_species_list = TreeSpecies.objects.filter(is_noc=False).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		context['len_aplist']=len_aplist
		# context['trees']=list(trees)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

		return render(request,'my_app/tigram/tabel_01.html',context)



def noc_report2(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Applicationform.objects.filter(is_noc=True)
	sel_sp = request.GET.get('sel_sp')
		# .aggregate(Sum('volume'))
	# created_date__gte=six_month_previous_date,
	# app_list['dict_of_percentages']=dict_of_percentages
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)
		# if sel_sp != '' and sel_sp != None:
		# 	app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		# else:

		#ajax procedure
		# app_list=app_list.values('reason_office')
		# app_list=app_list.filter(application_status='A')
		totalapp=app_list.count()
		app_list=app_list.values(
		'created_date').annotate(
		no_of_applicantions=Count('id')
		).order_by('created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		# trees=load_tree_species()

		trees_species_list = TreeSpecies.objects.filter(is_noc=True).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		context['len_aplist']=len_aplist
		# context['trees']=list(trees)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)

	return render(request,'my_app/tigram/tabel_01.html',context)

def noc_report(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=True)
	sel_sp = request.GET.get('sel_sp')
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		if range_name=="" or range_name == None :
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('species_of_tree','appform__destination_details',
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		volume_sum=Sum('volume')
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.filter(is_noc=True).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)
	return render(request,'my_app/tigram/tabel_01.html',context)

def timber_trace(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	app_list = ScanedDetails_View.objects.all()
	checkpost = request.GET.get('checkpost')
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)

	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(app_form__area_range__icontains=range_name[0].range_name.name)
	else:
		if range_name=="" or range_name == None :
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			app_list = app_list.filter(app_form__division__icontains=div_name[0].division_name.name)
		else:
			app_list = app_list.filter(app_form__area_range__icontains=range_name)

	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))

			app_list=app_list.filter(app_form__created_date__gte=six_month_previous_date)
		else:


			if from_date !='' and from_date != None and from_date != 'None'  :


				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(app_form__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':

				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(app_form__created_date__lte=date_)
		if checkpost != '' and checkpost != None:

			app_list=app_list.filter(checkpost__checkpost_name=checkpost)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('checkpost_officer__name','scan_date','app_form__created_date','app_form__transit_pass_id','app_form__application_no','checkpost__checkpost_name'
		).order_by('app_form__created_date')
		len_aplist = len(app_list)
		context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.all().values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		checkpost_data = CheckPost.objects.all().values('checkpost_name')
		context['checkpost_name_values'] = list(checkpost_data)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))

			app_list=app_list.filter(scan_date=six_month_previous_date)
		else:


			if from_date !='' and from_date != None and from_date != 'None'  :


				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(scan_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':

				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(scan_date__lte=date_)


		len_aplist = len(app_list)
	return render(request,'my_app/tigram/tabel_01.html',context)

def timber_trace_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)
	app_list = ScanedDetails_View.objects.all()
	checkpost = request.GET.get('checkpost')
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)

	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		app_list = app_list.filter(app_form__area_range__icontains=range_name.range_name.name)
	else:

		app_list = ScanedDetails_View.objects.all()


	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))

			app_list=app_list.filter(app_form__created_date__gte=six_month_previous_date)
		else:


			if from_date !='' and from_date != None and from_date != 'None'  :


				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(app_form__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':

				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(app_form__created_date__lte=date_)
		if checkpost != '' and checkpost != None:

			app_list=app_list.filter(checkpost__checkpost_name=checkpost)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('checkpost_officer__name','scan_date','app_form__created_date','app_form__transit_pass_id','app_form__application_no','checkpost__checkpost_name'
		).order_by('app_form__created_date')
		len_aplist = len(app_list)
		context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.all().values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		checkpost_data = CheckPost.objects.all().values('checkpost_name')
		context['checkpost_name_values'] = list(checkpost_data)
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))

			app_list=app_list.filter(scan_date=six_month_previous_date)
		else:


			if from_date !='' and from_date != None and from_date != 'None'  :


				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(scan_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':

				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(scan_date__lte=date_)


		len_aplist = len(app_list)
	return render(request,'my_app/tigram/tabel_01.html',context)

def noc_report_admin(request):
	context={}
	groups=request.user.groups.values_list('name',flat = True)
	select_mon = request.GET.get('select_mon',None)
	# context['group'] = groups
	current_date = date.today()
	from_date = request.GET.get('from_date',None)
	to_date = request.GET.get('to_date',None)

	app_list = Timberlogdetails.objects.filter(appform__is_noc=True)
	sel_sp = request.GET.get('sel_sp')
	range_name = request.GET.get('range_name',None)
	div_name = request.GET.get('div_name',None)
	if request.user.groups.filter(name__in=['revenue officer','deputy range officer','forest range officer']).exists():
		if groups[0] in ['revenue officer']:
			range_name = RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
		else:
			range_name = ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
		# app_list = app_list.filter(appform__area_range__icontains=range_name[0].range_name.name)
	else:
		if range_name=="" or range_name == None :
			div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id)
			# app_list = app_list.filter(appform__division__icontains=div_name[0].division_name.name)
		else:
			app_list = app_list.filter(appform__area_range__icontains=range_name)
	# context['dict_of_percentages'] =dict_of_percentages
	# context['app_list'] = app_list
	if request.is_ajax():
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(appform__created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(appform__created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(appform__created_date__lte=date_)
		if sel_sp != '' and sel_sp != None:
			app_list=app_list.filter(species_of_tree__icontains=sel_sp)
		#ajax procedure
		# app_list=app_list.values('reason_office')
		app_list=app_list.values('species_of_tree','appform__destination_details',
		'appform__created_date').annotate(
		 no_of_trees=Count('species_of_tree')
		).annotate(
		volume_sum=Sum('volume')
		).order_by('appform__created_date')
		len_aplist = len(app_list)

		context['applicantions']=list(app_list)
		trees_species_list = TreeSpecies.objects.filter(is_noc=True).values('name')
		context['trees_species'] = list(trees_species_list)
		context['trees_species_length']=len(context['trees_species'])
		# context['group'] = list(groups)
		return JsonResponse(context,safe=False)
	else:
		if (select_mon is  None or select_mon =='') and (from_date is  None or from_date=='') and (to_date is  None or to_date=='' ):
			select_mon = 6
		if  select_mon !='' and select_mon !=  None :

			months_ago = float(select_mon)
			# months_ago = float(select_mon) if select_mon is not None else 3 #12
			six_month_previous_date = current_date - timedelta(days=(months_ago * 365 / 12))
			app_list=app_list.filter(created_date__gte=six_month_previous_date)
		else:

			if from_date !='' and from_date != None and from_date != 'None'  :

				date_ = datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(from_date,'%Y-%m-%d')
				# from_date=d.strftime(from_date)
				app_list=app_list.filter(created_date__gte=date_)
			if to_date !='' and to_date != None and to_date != 'None':
				date_ = datetime.strptime(to_date, "%Y-%m-%d").strftime('%Y-%m-%d')
				# d=datetime.strptime(to_date,'%Y-%m-%d')
				# to_date=d.strftime(to_date)
				app_list=app_list.filter(created_date__lte=date_)

		len_aplist = len(app_list)
	return render(request,'my_app/tigram/tabel_01.html',context)



@login_required(login_url='staff_login')
@group_required('revenue officer','deputy range officer','forest range officer','division officer','state officer')
def all_reports(request):
	context={}
	context['area_range_name']=request.GET.get('range_name',None)
	context['area_div_name']=request.GET.get('div_name',None)
	context['groups']=request.user.groups.values_list('name',flat = True)
	context['current_page']='report_section'

	if context['groups'][0] == 'division officer':
		context['area_range_name']= "" if context['area_range_name'] == "" or context['area_range_name']==None else context['area_range_name']
		div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id).values_list('division_name',flat=True)
		context['area_range'] =Range.objects.filter(division_id=div_name[0]).values_list('name',flat=True)
	if context['groups'][0] == 'state officer':
		context['area_div_name']= "" if context['area_div_name'] == "" or context['area_div_name']==None else context['area_div_name']
		context['area_range_name']= "" if context['area_range_name'] == "" or context['area_range_name']==None else context['area_range_name']
		context['division_name'] = Division.objects.filter(is_delete=False).values_list('name',flat=True)
		# context['area_range'] =Range.objects.filter(division_id=div_name[0]).values_list('name',flat=True)
		div_id=context['area_div_name']
		if div_id.isdigit():
			context['area_range'] = Range.objects.filter(division_id=div_id,is_delete=False).values_list('name',flat=True)
		else:
			context['area_range'] = Range.objects.filter(division__name__iexact=div_id,is_delete=False).values_list('name',flat=True)

		if len(context['area_range'])<1 and div_id=="" or div_id==None:
			context['area_range'] = Range.objects.filter(is_delete=False).values_list('name',flat=True)
		# context['area_range'] = Range.objects.filter(division__icontains=div_name)
	return render(request,'my_app/tigram/reports_tables_02.html',context)


@login_required(login_url='staff_login')
@group_required('revenue officer','deputy range officer','forest range officer','division officer','state officer')
def all_admin_reports(request):
	context={}
	context['area_range_name']=request.GET.get('range_name',None)
	context['area_div_name']=request.GET.get('div_name',None)
	context['groups']=request.user.groups.values_list('name',flat = True)
	context['current_page']='report_section'

	context['divi']=Division.objects.all().order_by('name').values_list('name',flat=True)
	# context['range']=Range.objects.all().values_list('name',flat=True)
	context['range']=Range.objects.filter(division__name=context['area_div_name']).order_by('name').values_list('name',flat = True)
	range_name = request.GET.get('range_name')

	context['area_range_name']= "" if context['area_range_name'] == "" or context['area_range_name']==None else context['area_range_name']
	div_name = DivisionOfficerdetail.objects.filter(div_user_id=request.user.id).values_list('division_name',flat=True)
	# context['area_range'] =Range.objects.filter(division_id=div_name[0]).values_list('name',flat=True)

	context['area_div_name']= "" if context['area_div_name'] == "" or context['area_div_name']==None else context['area_div_name']
	context['area_range_name']= "" if context['area_range_name'] == "" or context['area_range_name']==None else context['area_range_name']
	context['division_name'] = Division.objects.filter(is_delete=False).values_list('name',flat=True)
		# context['area_range'] =Range.objects.filter(division_id=div_name[0]).values_list('name',flat=True)
	div_id=context['area_div_name']
	if div_id.isdigit():
		context['area_range'] = Range.objects.filter(division_id=div_id,is_delete=False).values_list('name',flat=True)
	else:
		context['area_range'] = Range.objects.filter(division__name__iexact=div_id,is_delete=False).values_list('name',flat=True)
	if len(context['area_range'])<1 and div_id=="" or div_id==None:
		context['area_range'] = Range.objects.filter(is_delete=False).values_list('name',flat=True)
		# context['area_range'] = Range.objects.filter(division__icontains=div_name)
	return render(request,'my_app/tigram/admin/view_reports.html',context)






def scanqr(request,code):
	url = code.rsplit('/', 1)[-1]
	tp = TransitPass.objects.filter(qr_code=url)
	if request.user.id is not None:

		groups=request.user.groups.values_list('name',flat=True)
		user_id = request.user.id
		if tp:
			if groups[0]=='user' and tp[0].app_form.by_user_id!=user_id:
				return HttpResponseNotFound('<h1>Page Not Found! </h1>')
			return HttpResponseRedirect(reverse('transit_pass_pdf', kwargs={'applicant_no':tp[0].app_form_id}))
			# return render(request,"my_app/tigram/newpassword.html",{})
		else:
			return HttpResponseNotFound('<h1>Page Not Found! </h1>')
	else:
		context={}
		if tp:
			application = Applicationform.objects.filter(id=tp[0].app_form_id)
			if application:
			#	authorizer_name = application[0].approved_by.name
			#	context['authorizer_name'] = authorizer_name
				application=application.values()
				context['applications']=application
			log_details = Timberlogdetails.objects.filter(appform_id=tp[0].app_form_id).values()
			context['tp']=tp[0]
			# Applicationform
			context['log_details']=log_details
		return render(request,'my_app/tigram/transit_pass_scan.html',context)
		# return HttpResponseNotFound('<h1>Page Not Found! </h1>')
	return HttpResponseNotFound('<h1>Page Not Found! </h1>')






















@login_required

@group_permissions('scan_logqr')
def scan_logqr(request,code):
	url = code.rsplit('/', 1)[-1]
	groups=request.user.groups.values_list('name',flat = True)
	tp = Timberlogdetails.objects.filter(log_qr_code=url)
	user_id = request.user.id
	if tp:
		if groups[0]=='user' and tp[0].appform.by_user_id!=user_id:
			return HttpResponseNotFound('<h1>Page Not Found! </h1>')
		# return redirect()
		return HttpResponseRedirect(reverse('log_qrcode_pdf', kwargs={'log_no':tp[0].id}))
		# return render(request,"my_app/tigram/newpassword.html",{})
	else:
		return HttpResponseNotFound('<h1>Page Not Found! </h1>')
	return HttpResponseNotFound('<h1>Page Not Found! </h1>')



def view_reasons(request):
	applicants =  Applicationform.objects.filter(created_date='27/7/2020')
	return JsonResponse({'applicants':applicants})


def test_sample():
	# temp=Applicationform.objects.filter(transit_pass_created_date__gt=datetime.datetime.today()-datetime.timedelta(days=20)).update(
	# 	tp_expiry_date=datetime.datetime.today(),tp_expiry_status=True
	# 	)
	temp=Applicationform.objects.filter(transit_pass_created_date__gt=date.today()-timedelta(days=20)).update(
		tp_expiry_date=date.today(),tp_expiry_status=True
		)
	#


def clear_login_attemps():
    attempts = LoginAttempts.objects.all().delete()
    
def approve_deemed():
 try:
  attempts = OtpAttemps.objects.all()
  for a in attempts:
   delta = datetime.today()-datetime.strptime(a.last_otp_date, '%Y-%m-%d %H:%M:%S.%f')
   if delta.days > 1:
    OtpAttemps.objects.get(id = a.id).delete()
 except:
     pass
 
 
 all_u = CustomUser.objects.filter(mobile_verified = "False")
 for each in  all_u:
  groups= each.groups.values_list('name',flat = True)
  try:
   if groups[0] == "user":
       each.delete()
  except:
      pass

	#
 app_id_list=Applicationform.objects.filter(
 verify_office = True,is_noc=False,
 deemed_approval=False,
	# transit_pass_id__isnull=True,
 verify_office_date__lt=date.today()-timedelta(days=21)).exclude(Q(application_status='A')|Q(application_status='R')).values_list('id',flat=True)
 if len(app_id_list)<1:

  return True
 for app_id in app_id_list:
				application_detail = Applicationform.objects.filter(id=app_id)
				vehicle_detail = Vehicle_detials.objects.filter(app_form_id=app_id)
				qr_code=get_qr_code(app_id)
				qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
				is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
				if is_timber:
					for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
						log_qr_code=get_log_qr_code(app_id,each_timber['id'])

						log_data='Log Details:\n'
						log_data+='Application No. :-'+application_detail[0].application_no+'\n'
						log_data+='Destination :-'+application_detail[0].destination_details+'\n'
						log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
						log_data+='Length :-'+str(each_timber['length'])+'\n'
						log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
						log_data+='Volume :-'+str(each_timber['volume'])+'\n'
						log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
						log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
						log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
						is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img)

				if vehicle_detail:
					# vehicle=vehicle_detail[0]
					transit_pass=TransitPass.objects.create(
						vehicle_reg_no=vehicle_detail[0].vehicle_reg_no,
						driver_name = vehicle_detail[0].driver_name,
						driver_phone = vehicle_detail[0].driver_phone,
						mode_of_transport = vehicle_detail[0].mode_of_transport,
						license_image = vehicle_detail[0].license_image,
						photo_of_vehicle_with_number = vehicle_detail[0].photo_of_vehicle_with_number,
						state = application_detail[0].state,
						district = application_detail[0].district,
						taluka = application_detail[0].taluka,
						block = application_detail[0].block,
						village = application_detail[0].village,
						qr_code = qr_code,
						qr_code_img =qr_img,
						app_form_id = app_id
					)
				else:
					transit_pass=TransitPass.objects.create(
						state = application_detail[0].state,
						district = application_detail[0].district,
						taluka = application_detail[0].taluka,
						block = application_detail[0].block,
						village = application_detail[0].village,
						qr_code = qr_code,
						qr_code_img =qr_img,
						app_form_id = app_id
					)
				application_detail.update(
					# reason_range_officer = reason ,
				 application_status = 'A',
					# approved_by = request.user,
					# verify_range_officer = True,
					# range_officer_date = date.today(),
					transit_pass_id=transit_pass.id,
					transit_pass_created_date = date.today(),
					)
 temp=Applicationform.objects.filter(
	verify_office = True,is_noc=False,
	# deemed_approval=False,
	verify_office_date__lt=date.today()-timedelta(days=21)).update(
	deemed_approval=True,transit_pass_created_date=date.today()
	)

def approve_deemed_form_two_1():
	#
	app_id_list=Applicationform.objects.filter(
	verify_office = True,is_noc=False,log_updated_by_user=False,
	deemed_approval_1=False,is_form_two=True,verify_forest1=False,
	verify_office_date__lt=date.today()-timedelta(days=21)).exclude(Q(application_status='A')|Q(application_status='R')).update(
		deemed_approval_1=True,
	)


def approve_deemed_form_two():
	#
	app_id_list=Applicationform.objects.filter(
	verify_office = True,is_noc=False,log_updated_by_user=True,
	deemed_approval=False,is_form_two=True,
	appsecond_two_date__lt=date.today()-timedelta(days=21)).exclude(Q(application_status='A')|Q(application_status='R')).values_list('id',flat=True)
	if len(app_id_list)<1:
		return True
	for app_id in app_id_list:
				application_detail = Applicationform.objects.filter(id=app_id)
				vehicle_detail = Vehicle_detials.objects.filter(app_form_id=app_id)
				qr_code=get_qr_code(app_id)
				qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
				is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
				if is_timber:
					for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
						log_qr_code=get_log_qr_code(app_id,each_timber['id'])
						log_data='Log Details:\n'
						log_data+='Application No. :-'+application_detail[0].application_no+'\n'
						log_data+='Destination :-'+application_detail[0].destination_details+'\n'
						log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
						log_data+='Length :-'+str(each_timber['length'])+'\n'
						log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
						log_data+='Volume :-'+str(each_timber['volume'])+'\n'
						log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
						log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
						log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
						is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img)

				if vehicle_detail:
					# vehicle=vehicle_detail[0]
					transit_pass=TransitPass.objects.create(
						vehicle_reg_no=vehicle_detail[0].vehicle_reg_no,
						driver_name = vehicle_detail[0].driver_name,
						driver_phone = vehicle_detail[0].driver_phone,
						mode_of_transport = vehicle_detail[0].mode_of_transport,
						license_image = vehicle_detail[0].license_image,
						photo_of_vehicle_with_number = vehicle_detail[0].photo_of_vehicle_with_number,
						state = application_detail[0].state,
						district = application_detail[0].district,
						taluka = application_detail[0].taluka,
						block = application_detail[0].block,
						village = application_detail[0].village,
						qr_code = qr_code,
						qr_code_img =qr_img,
						app_form_id = app_id
					)
				else:
					transit_pass=TransitPass.objects.create(
						state = application_detail[0].state,
						district = application_detail[0].district,
						taluka = application_detail[0].taluka,
						block = application_detail[0].block,
						village = application_detail[0].village,
						qr_code = qr_code,
						qr_code_img =qr_img,
						app_form_id = app_id
					)
				application_detail.update(
					# reason_range_officer = reason ,
				 application_status = 'A',
					# approved_by = request.user,
					# verify_range_officer = True,
					# range_officer_date = date.today(),
					deemed_approval=True,
					transit_pass_id=transit_pass.id,
					transit_pass_created_date = date.today(),
					)
	# temp=Applicationform.objects.filter(
	# verify_office = True,is_noc=False,is_form_two=True,
	# # deemed_approval=False,
	# verify_office_date__lt=date.today()-timedelta(days=7)).update(
	# deemed_approval=True,transit_pass_created_date=date.today()
	# )


class Location(TemplateView):
	template_name = 'my_app/tigram/location_python.html'


@login_required
def location_view(request,app_id):
 groups=request.user.groups.values_list('name',flat = True)
 if groups[0] == "user":
  app = Applicationform.objects.get(id=app_id)
  if request.user != app.by_user:
   return HttpResponse("Not Authorized")      
 context = {}

 loc=image_documents.objects.get(app_form_id=app_id)
 lat = loc.image1_lat
 lon = loc.image2_lat
 image1_lat = loc.image1_lat
 image2_lat = loc.image2_lat
 image3_lat = loc.image3_lat
 image4_lat = loc.image4_lat
 image1_log = loc.image1_log
 image2_log = loc.image2_log
 image3_log = loc.image3_log
 image4_log = loc.image4_log
 scan_details = list(ScanedDetails_View.objects.filter(app_form_id=app_id).values('check_lat','check_log'))
 

 scan_details_values = json.dumps(scan_details)
 return render(request, 'my_app/tigram/leaflet.html',{
     'image1_lat' : image1_lat,
 'image2_lat' : image2_lat,
 'image3_lat' : image3_lat,
 'image4_lat' : image4_lat,
 'image1_log' : image1_log,
 'image2_log' : image2_log,
 'image3_log' : image3_log,
 'image4_log' : image4_log,
     'lat':lat,'lon':lon, 'scan_details_values':scan_details_values})


def need_field_verification(request,app_id):
	field = Applicationform.objects.get(id=app_id)
	field.location_needed= True
	field.save()
	return JsonResponse({'message':'Assigned Successfully!'})

def success_field_verification(request,app_id):
	Applicationform.objects.filter(id=app_id).update(status = True)
	return JsonResponse({'message':'Field Verification Success!'})

def failed_field_verification(request,app_id):
	Applicationform.objects.filter(id=app_id).update(status = False)
	return JsonResponse({'message':'Field Verification Failed!'})

def Scaned(request):
	context = {}
	details= ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id)

	return render(request, 'my_app/tigram/scan_details.html', {'details':details})
def UserScaned(request):
	context = {}
	details= ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id)

	return render(request, 'my_app/tigram/user_scan.html', {'details':details})


def load_timber1(request):

	div_list = TreeSpecies.objects.all().values('id','name')

	return JsonResponse({'div_list':div_list})


def create_buyerseller(request):
	if request.method == 'POST':
		user_id = request.user.id
		address = request.POST.get('address')
		pincode = request.POST.get('pincode')
		name = request.POST.get('name')
		phone = request.POST.get('phone')
		division = request.POST.get('division')
		quantity = request.POST.get('quantity')
		dist = request.POST.get('dist')
		timber_name = request.POST.get('timber_name')
		timber_image= request.FILES.get('timber_image')
		url = 'media/upload/timber_image/'
		saved_image = upload_timber_image_file(user_id, timber_image, url, 'TimberImage')
		if address != "" and name != "" and phone != "" and division != "" and quantity != "" and dist != "" and timber_name != "":
			check= Buyer_Seller.objects.create(
				address=address,
				pincode=pincode,
				name=name,
				phone=phone,
				timber_image=timber_image,
				timber_name=timber_name,
				by_user_id = request.user.id,
				quantity=quantity,
				division=division,
				dist=dist
				)
			return JsonResponse({'message':'Success!','response_code':'success'})
	return JsonResponse({'message':'Failed!','response_code':'fail'})


def Buyer_Seller_Data(request):

	context = {}
	context['timber'] = TreeSpecies.objects.all()
	context['add_data'] = Buyer_Seller.objects.filter(by_user_id=request.user.id, status="active")
	context['sel_data'] = Buyer_Seller.objects.filter(by_user_id=request.user.id, status="active", selected=True)
	context['all_data'] = Buyer_Requirement.objects.filter(status="active")
	context['division_areas'] = Division.objects.filter(is_delete=False).order_by('name').values('name')
	context['district_name'] = District.objects.all().order_by('district_name').values('district_name')
	context['species'] = TreeSpecies.objects.all().order_by('name')
	return render(request, 'my_app/tigram/buyer_seller.html',context)

def deletedata(request,id):
	data = Buyer_Seller.objects.get(id=id)
	data.status = "delete"
	data.save()
	messages.success(request,"successfully deleted")
	return redirect('Buyer_Seller_Data')


def webgis_map(request):

	return render(request, 'my_app/tigram/webgismap.html')

def Buyer_Data(request):

	context = {}
	status = CustomUser.objects.get(id = request.user.id)
	if status.firmstatus:
		context['timber'] = TreeSpecies.objects.all()
		context['add_data'] = Buyer_Requirement.objects.filter(by_user_id=request.user.id, status="active")
		context['all_data'] = Buyer_Seller.objects.filter(status="active", selected=False).exclude(by_user_id=request.user.id)
		context['sel_data'] = Buyer_Seller.objects.filter(status="active", selected=True)
		context['division_areas'] = Division.objects.filter(is_delete=False).order_by('name')
		context['district_name'] = District.objects.all().order_by('district_name')
		context['species'] = TreeSpecies.objects.all().order_by('name')
		return render(request, 'my_app/tigram/buyer1.html',context)
	else:
		return redirect('firmregistration')

def buyer_requirement(request):
	if request.method == 'POST':
		user_id = request.user.id
		address = request.POST.get('address')
		name = request.POST.get('name')
		phone = request.POST.get('phone')
		division = request.POST.get('division')
		quantity = request.POST.get('quantity')
		dist = request.POST.get('dist')
		timber_name = request.POST.get('timber_name')
		if address!="" and  name!="" and phone!="" and division!="" and quantity!="" and dist!="" and timber_name!="":
			check= Buyer_Requirement.objects.create(
				address=address,
				name=name,
				phone=phone,
				timber_name=timber_name,
				by_user_id = request.user.id,
				quantity=quantity,
				division=division,
				dist=dist
				)
			
			messages.error(request,'Successfully Added')
			return JsonResponse({'message':'Success!','response_code':'success'})
	messages.error(request,'Please Fill All The Data')
	return JsonResponse({'message':'Failed!','response_code':'fail'})


def selected(request,id):
	data = Buyer_Seller.objects.get(id=id)
	data.selected = True
	data.save()
	messages.success(request,"Selected successfullly")
	return redirect('Buyer_Seller_Data')

def firmregistration(request):

	user = CustomUser.objects.get(id=request.user.id)
	if request.method == 'POST':
		id = request.user.id
		organization = request.POST.get('organization')
		pan_card = request.POST.get('pan_card')
		gst = request.POST.get('gst')
		cin_number = request.POST.get('cin_number')
		tan_number = request.POST.get('tan_number')
		service_tax = request.POST.get('service_tax')
		website = request.POST.get('website')
		if organization:
			obj = FirmUser()
			obj.user_id = id
			obj.organization = organization
			obj.pan_card = pan_card
			obj.gst = gst
			obj.cin_number = cin_number
			obj.tan_number = tan_number
			obj.service_tax = service_tax
			obj.website = website
			obj.save()
			user.usr_category = "firm"
		else:
			user.usr_category = "individual"
		user.firmstatus = True
		user.save()
		messages.success(request,"Saved Successfully")
		return redirect('Buyer_Data')
	return render(request,'my_app/tigram/category.html')

def register_Otp_verify(request):

	if request.method == 'POST':
		phone = request.POST.get('phone')
		otp = request.POST.get('otp')
		user_Exist = CustomUser.objects.filter(phone=phone,mobile_otp=otp)
		if user_Exist:
			data = CustomUser.objects.get(phone=phone, mobile_otp=otp)
			db_time = data.mobile_otp_created_time
			datetime_obj = datetime.strptime(db_time,'%Y-%m-%d %H:%M:%S.%f')
			now = datetime.now()
			time_difference = now - datetime_obj
			if time_difference > timedelta(minutes=3):
				message = "OTP expired"
				return render(request, "my_app/tigram/registration.html", {"phone": phone, "message": message})
			else:
				CustomUser.objects.filter(phone=phone).update(mobile_verified='True')
				message = "Registered successfully"
				return render(request, "my_app/tigram/ulogin.html", {"phone": phone,"message":message})
	

		else:
			user_Existt = CustomUser.objects.get(phone=phone)
			attempts =user_Existt.no_of_attempts_register
			val=int(attempts)
			val=val+1
			CustomUser.objects.filter(phone=phone).update(no_of_attempts_register=val)
			if val > 3:
				message = "You execeded the limit please try after sometime"
				return render(request, "my_app/tigram/register_otp.html",{"temp": "Wrong otp entered.", "phone": phone, "message": message})
			else:
				message = "Invalid OPT"
				return render(request, "my_app/tigram/register_otpverifications.html",{"temp": "Wrong otp entered.", "phone": phone, "message": message})

	return render(request,"my_app/tigram/otpverification.html")

def sendSingleSMS_new(username, encryp_password, senderid, message, mobileno,templateid, deptSecureKey):
      
      key = hashlib.sha512((username+senderid+message+deptSecureKey).encode()).hexdigest()
      data = {
        "username": username.strip(),
        "password": encryp_password.strip(),
        "senderid": senderid.strip(),
        "content": message.strip(),
        "smsservicetype": "singlemsg",
        "mobileno": mobileno.strip(),
		"templateid": templateid.strip(),
        "key": key.strip()
      }
      response = requests.post("https://msdgweb.mgov.gov.in/esms/sendsmsrequestDLT", data=data)
      return response.text
  
import math, random
def new_otp_generateOTP() :
    digits = "0123456789"
    OTP = ""
    for i in range(6) :
        OTP += digits[math.floor(random.random() * 10)]

    return OTP
def register_otp_verification(request):
 context = {}
 mobile = request.POST.get('phone')
 data=CustomUser.objects.filter(phone=mobile)
 
 if data:
  current_time =datetime.now()
  otp = new_otp_generateOTP()
  CustomUser.objects.filter(phone=mobile).update(mobile_otp=otp,no_of_attempts_register='0',mobile_otp_created_time=current_time)
  USERNAME = "KERALAFOREST-KFDSER"
  PASSWORD = "Fmis@2021"
  SENDERID = "KFDSER"
  KEY = "98a52a38-b8fe-42c8-8fa7-60ba10fc5cbc"
  content = "KeralaForestDept - Registration OTP for TIGRAM is "+"123456"+"."
  mobileno = "7095099857"
  templateid = "1407169907503070163"
  key = KEY
  
  message = "KeralaForestDept - Registration OTP for TIGRAM is "+str(otp)+"."
  if otp_check_brute(mobile) == False:
    message = "Exceded daily limit"
    return render(request, "my_app/tigram/register_otp.html",{"message":message}) 
  sendSingleSMS_new(USERNAME, PASSWORD, SENDERID, message, mobile, templateid, key)
  return render(request, "my_app/tigram/register_otpverifications.html",{"phone":mobile})
 message = "Please try again or Please verify your registered email or phone number with admin"
 return render(request, "my_app/tigram/register_otp.html",{"message":message})




@login_required
@group_required('revenue officer','deputy range officer','forest range officer','division officer','state officer')
def approve_recommended(request,app_id):
 if request.method == 'POST':
  app = request.POST['app_id']
  f = ApprovedTimberLog.objects.filter(appform_id =app)
  f.update(is_approved = False)
  for i in request.POST.getlist('ukeys[]'):
    a = int(i)
    t = ApprovedTimberLog.objects.get(id=a, appform_id =app)
    t.is_approved = True
    t.qr_data = get_qr_string(settings.SERVER_BASE_URL+"getapprovedtimberqr/"+str(a))
    t.save()
  return HttpResponse(request,"OKAY")

@login_required
@group_required('forest range officer','division officer','state officer')
def assign_deputy_for_cutting(request,app_id):
 if request.method == 'POST':
  app_id = app_id
  app = Applicationform.objects.filter(id= app_id)
  try:
      file = request.FILES['up_file']
      url = 'media/upload/range_remark_1/'
      img = upload_remark_range_image_file(app_id,file,url,"Range_reason_1")
      app.update(range_1_file = img ,current_app_status = "Deputy Range Officer Assigned for Field Verification")
  except:
      pass
  dep = request.POST['deputy_id']

  app.update(current_app_status = "Deputy Range Officer Assigned for Field Verification" , range_1_text = request.POST["remark_text"], r = request.user.id, d =  dep ,assigned_deputy2_by=request.user,assigned_deputy2_id = dep,approved_by_r = "Yes", assgn_deputy = 'assgned' , assigned_deputy2_date =date.today())
  messages.error(request,"Assigment is successful")
  return redirect('officer_dashboard')
 return redirect('officer_dashboard')

def upload_remark_range_image_file(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.RANGE_1_FILE
	# image_path = IMAGE_TAG[image_tag]
	if image_path=='form3':
		image_path = settings.RANGE_1_FILE
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]

				image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name


@login_required
@group_required('forest range officer','division officer','state officer')
def request_for_recheck(request,app_id):
 if request.method == 'POST':
  file = request.FILES['up_file']
  url = 'media/upload/recheck/'
  app_id = app_id
  img = upload_recheck_file(app_id,file,url,"Recheck")
  app = Applicationform.objects.filter(id= app_id)
  app.update( recheck_remark = request.POST["remark_text"] ,recheck_image = img , r = request.user.id)
  
  messages.error(request,"Requested for Recheck for user")
  return redirect('officer_dashboard')
 return redirect('officer_dashboard')




def upload_recheck_file(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.RECHECK_FILE
	# image_path = IMAGE_TAG[image_tag]
	if image_path=='form3':
		image_path = settings.RECHECK_FILE
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]

				image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name






@login_required
@group_required('forest range officer','division officer','state officer')
def approve_cutting_pass(request,app_id):
 if request.method == 'POST':
  app_id = app_id
  app = Applicationform.objects.filter(id= app_id)
  try:
   file = request.FILES['up_file']
   url = 'media/upload/range_remark_2/'
   app_id = app_id
   img = upload_range2_file(app_id,file,url,"Range_reason_2")
   app.update(range_2_file = img,  ) 
  except: 
      pass
  
  if request.POST["action"] == "Approve":
   app.update(current_app_status = "Approved By Range Officer",range_2_text = request.POST["remark_text"] , r = request.user.id, application_status = "A", confirm_date = date.today())
   logs  = request.POST.getlist('sel_approve')
   for l in logs:
    a = ApprovedTimberLog.objects.filter(id = l)
    a.update(is_approved = True)
   messages.error(request,"Application has been approved successfully")
  elif request.POST["action"] == "Reject":
    app.update( range_2_text = request.POST["remark_text"] , r = request.user.id, application_status = "R",current_app_status = "Rejected By Range Officer",confirm_date = date.today())
    messages.error(request,"Application has been Rejected")
  return redirect('officer_dashboard')





def upload_range2_file(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.RANGE_2_FILE
	# image_path = IMAGE_TAG[image_tag]
	if image_path=='form3':
		image_path = settings.RANGE_2_FILE
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]

				image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name


@login_required
@group_required('forest range officer','division officer','state officer')
def reject_cutting_pass(request,app_id):
 if request.method == 'POST':
  app = Applicationform.objects.filter(id= app_id)
  try:
   file = request.FILES['up_file']
   url = 'media/upload/range_remark_1/'
   app_id = app_id
   img = upload_remark_range_image_file(app_id,file,url,"Range_reason_1")
   app.update(range_1_file = img )
  except:
   pass
  
  app.update( range_1_text = request.POST["remark_text"] , r = request.user.id, application_status = "R" ,current_app_status = "Rejected By Range Officer")
  messages.error(request,"Application has been Rejected")
  return redirect('officer_dashboard')
 return redirect('officer_dashboard')

@login_required
@group_required('forest range officer','division officer','state officer')
def reject_cutting_pass_2(request,app_id):
 if request.method == 'POST':
  file = request.FILES['up_file']
  url = 'media/upload/range_remark_1/'
  app_id = app_id
  img = upload_remark_range_image_file_2(app_id,file,url,"Range_reason_2")
  app = Applicationform.objects.filter(id= app_id)
  app.update( range_2_text = request.POST["remark_text"] ,range_2_file = img , r = request.user.id, application_status = "R" , current_app_status = "Rejected By Range Officer")
  messages.error(request,"Application has been Rejected")
  return redirect('officer_dashboard')

def upload_remark_range_image_file_2(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.RANGE_2_FILE
	# image_path = IMAGE_TAG[image_tag]
	if image_path=='form3':
		image_path = settings.RANGE_2_FILE
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]

				image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name



@login_required
@never_cache
@group_permissions('application_view')
def application_view_transit(request,pk):
 transit = TransitPass.objects.get(transit_number=pk)
 app = Applicationform.objects.get(id = transit.app_form.id)
 groups=request.user.groups.values_list('name',flat = True)
 if groups[0] == "user":
  if request.user != app.by_user:
   return HttpResponse("Not Authorized")
 if request.method == "POST":
  transit = TransitPass.objects.get(transit_number=pk)
  app = Applicationform.objects.get(id = transit.app_form.id)
  try:
   file = request.FILES['remark_file']
   url = 'media/upload/transit_remark/'
   img = upload_remark_transit_image_file(transit.transit_number,file,url,"transit_remark")
   transit.remarks_img = img
  except:
    transit.remarks_img = ""
  if request.POST['action']=="Approve":   
   if app.application_status == "A":
    # check_list = request.POST.getlist('states[]')
    # for c in check_list:
    #  che = CheckPostPassTransit(app=app,transit=transit ,checkpost_id = int(c))
    #  che.save()
    transit.remarks = request.POST['remark_text']
    transit.transit_status = "Approved" 
    all_logs =  ProductTransit.objects.filter(transit_pass = transit).update(is_transit_approved = 2)    
    logs = request.POST.getlist('logs_to_approve')
    for log in logs:
     t = ProductTransit.objects.get(id = int(log))
     t.is_transit_approved = 1
     t.qr_data = get_qr_string(settings.SERVER_BASE_URL+"getproductqr/"+str(log))
     t.save()  
    qr_code = get_qr_code(pk)
    transit.qr_code=qr_code
    transit.qr_code_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, pk)
    transit.save()
    messages.error(request,"Transit Pass Approved")
  else:
    transit.transit_status = "Rejected" 
    transit.remarks = request.POST['remark_text']
    all_logs =  ProductTransit.objects.filter(transit_pass = transit).update(is_transit_approved = 2)
    transit.save()
    messages.error(request,"Transit Pass Rejected")










  return redirect('officer_dashboard')
 context = {}

 context['transit'] = TransitPass.objects.get(transit_number=pk)

 context['application'] = Applicationform.objects.get(id = context['transit'].app_form.id)
 cuurent_request = ProductTransit.objects.filter(transit_pass = context['transit'])
 previous_transits = ProductTransit.objects.filter(app= context['transit'].app_form.id)
 list_of_dicts = []
 for each in previous_transits:
     list_of_dicts.append(each.__dict__)
 selected_key = "approved_timber_id"
 result_dict = {}

 for item in list_of_dicts:
    key_value = item[selected_key]
    if key_value not in result_dict:
        result_dict[key_value] = []
    result_dict[key_value].append(item)
 result_list = [{"key": key, "values": value} for key, value in result_dict.items()]
 logs = []
 for each in result_list:
     name = ApprovedTimberLog.objects.get(id=each['key'])
     logs.append(name)
 context['logs'] = zip(logs,result_list)
 
 list_of_dicts = []
 for each in cuurent_request:
     list_of_dicts.append(each.__dict__)
 selected_key = "approved_timber_id"
 result_dict = {}

 for item in list_of_dicts:
    key_value = item[selected_key]
    if key_value not in result_dict:
        result_dict[key_value] = []
    result_dict[key_value].append(item)
 result_list = [{"key": key, "values": value} for key, value in result_dict.items()]
 logs = []
 for each in result_list:
     name = ApprovedTimberLog.objects.get(id=each['key'])
     logs.append(name)
  
 context['curent_request'] = zip(logs,result_list)
 
 context['image_documents'] = image_documents.objects.get(app_form= context['transit'].app_form)
 return render(request,"my_app/tigram/application_view_transit.html",context=context)

@login_required
@never_cache
def add_transit(request,app_id):
 if request.method == "POST":
  app = Applicationform.objects.get(id=app_id)
  transit = TransitPass()
  transit.save()
  transit = TransitPass(id=transit.id)
  x = app.application_no.replace("/", "-")
  transit.transit_number = 'TP-'+str(x) +str(transit.id)
  transit.app_form = app
  if app.application_status == "A":
   transit.transit_status = "Pending"
   transit.destination_details = request.POST['destination']
   transit.destination_district = request.POST['district']
   logs = request.POST['pro_data']
   logs = json.loads(logs)
   transit.district = app.district
   transit.taluka = app.taluka
   transit.block = app.block
   transit.village = app.village
   for log in logs:
    admit = ProductTransit()
    admit.app= app 
    admit.approved_timber = ApprovedTimberLog.objects.get(id= log['timber_id']) 
    admit.transit_pass = transit 
    if log['product_type']=="Log": 
        admit.product = log['product_type'] 
        admit.log_height = log['height']
        admit.log_mdh = log['mdh'] 
        
    elif log['product_type']=="Firewood":
        admit.product = log['product_type'] 
        admit.firewood_weight = log['weight']

    elif log['product_type']=="cuttings":
        admit.product = log['product_type']
        admit.swan_length = log['length']
        admit.swan_breadth = log['breadth']
        admit.swan_height = log['height']
        
    admit.is_transit_applied = True
    admit.save()
   transit.save()
   messages.error(request,"Transit Pass applied")












 return redirect('dashboard')


def get_zip_file(request,app_id):
 doc = image_documents.objects.get(app_form=app_id)
 app = Applicationform.objects.get(id=app_id )
 ownership = app.proof_of_ownership_of_tree

 file_names = [doc.aadhar_detail, doc.revenue_approval, doc.declaration, ownership]
 paths = [settings.AADHAR_IMAGE_PATH, settings.REVENUE_APPROVAL_PATH, settings.DECLARATION_PATH, settings.PROOF_OF_OWNERSHIP_PATH]
 compression = zipfile.ZIP_DEFLATED
 zf = zipfile.ZipFile("/home/ubuntu/timberproject/media/upload/RAWs.zip", mode="w")
 for file_name , path in zip(file_names, paths):
    zf.write(path+file_name, file_name, compress_type=compression)
 zf.close()
 fff = "/home/ubuntu/timberproject/media/upload/RAWs.zip"
 with io.open(fff, 'rb') as ready_file:
        plug_cleaning_into_stream(ready_file, fff )
        response = HttpResponse(ready_file.read(), content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename="ATTACHMENTS_'+str(app_id)+'.zip'
        return response


def plug_cleaning_into_stream(stream, filename):
    try:
        closer = getattr(stream, 'close')
        def new_closer():
            closer()
            os.remove(filename)
        setattr(stream, 'close', new_closer)
    except:
        raise
    
    
    
    

def upload_remark_transit_image_file(record_id, post_image, image_path, image_tag):
	image_name = ''
	image_path = settings.TRANSIT_FILE
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]

				image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name


def err_404(request, exception):
   
   return render(request, 'my_app/tigram/error_page.html', status=404)
def err_500(request):
   
   return render(request, 'my_app/tigram/error_page.html', status=500)
def err_400(request, exception):
   
   return render(request,'my_app/tigram/error_page.html')
def csrf_failure(request, reason=""):
   
   return render(request,'my_app/tigram/error_page.html')




def sanitize_image(img123): 
 given_image = img123

 exif_dict = piexif.load(given_image)
 if "GPS" in exif_dict and len(exif_dict["GPS"]) > 0:
    exif_dict["GPS"] = {}
    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, given_image)
 if "Exif" in exif_dict and len(exif_dict["Exif"]) > 0:
    exif_dict["Exif"] = {}
    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, given_image)
 return(given_image)



def media_access(request, path):
 
 try:
  
  access_granted = False
  user = request.user
  groups=user.groups.values_list('name',flat = True)
  if "User" in path:
   import re
   u = re.findall(r'\d+', path)[0]
   if groups[0] == "user":
    if int(request.user.id) != int(u):
        return HttpResponse("Not Authorized")
    i = sanitize_image('/home/ubuntu/timberproject/media/'+path)
    img = open(i, 'rb')   
    response = FileResponse(img)
    return response
  if user.is_authenticated:
   if user.is_staff:
    access_granted = True
   else:
    
    if groups[0]!="user":
     access_granted = True
    else:
     import re
     app_num = re.findall(r'\d+', path)[-1]

     app = Applicationform.objects.get(id = int(app_num))
     if app.by_user == user:
      access_granted = True

  if access_granted:
   if path.split(".")[1] == "pdf":
    # with open('/home/ubuntu/timberproject/media/'+path, 'r') as f:
    #  file_data = f.read()
    file_data = open('/home/ubuntu/timberproject/media/'+path, 'rb')
    response = HttpResponse(file_data, content_type='application/pdf')
    
    return response
   i = sanitize_image('/home/ubuntu/timberproject/media/'+path)
   img = open(i, 'rb')
   
   response = FileResponse(img)
   return response
  else:
   raise Exception("To check with api")
 except:
  try:
    
    def get_user_from_token(token):
     objs = AuthToken.objects.filter(token_key=token[:CONSTANTS.TOKEN_KEY_LENGTH])
     if len(objs) == 0:
        access_granted = False
     return objs.first().user  
    data = path.split("/")
    user = get_user_from_token(data[-1])
    
    access_granted = False
    if user.is_staff:
      access_granted = True
    else:
     groups=user.groups.values_list('name',flat = True)
    if groups[0]!="user":
     access_granted = True
    else:
     import re
     app_num = re.findall(r'\d+', data[-2])[-1]
     app = Applicationform.objects.get(id = int(app_num))
     if app.by_user == user:
      access_granted = True

    if access_granted:
     i = sanitize_image('/home/ubuntu/timberproject/media/'+path.replace("/"+data[-1], ""))
     img = open(i, 'rb')
     
     response = FileResponse(img)
     return response
    else:
     return HttpResponseForbidden('Not authorized to access this media.')
  except:     
    return HttpResponseForbidden('Not authorized to access this media.') 
  
  
  
def upload_new_user_image_file(record_id, post_image):
	image_name = ''
	image_path = settings.PROFILE_PATH
	if not os.path.exists(image_path):
		os.makedirs(image_path)
	image_name = None
	if post_image != '' and image_path != ''  and record_id !='':
		try:
			filename = post_image.name
			filearr = filename.split('.')
			arr_len = len(filearr)

			if len(filearr) > 1 :
				file_name = filearr[0]
				file_ext = filearr[arr_len-1]

				image_name ="User_"+str(record_id)+"_image."+str(file_ext)
				imagefile = str(image_path)+str(image_name)
				
				with open(imagefile, 'wb+') as destination:
					for chunk in post_image.chunks():
						destination.write(chunk)
		except Exception as Error:
			pass

	return image_name

def otp_check_brute(mob):
 phone = mob
 try:
  attempt = OtpAttemps.objects.get(phone=phone)
 except:
     attempt = False
 if attempt:
  if int(attempt.otp_count) < 3:
   a = int(attempt.otp_count) + 1
   attempt.otp_count = a
   attempt.last_otp_date = str(datetime.today())
   attempt.save()
   return True
  else:
   return False
 else:
  OtpAttemps.objects.create(phone = phone, otp_count =1, last_otp_date = str(datetime.today()))
  return True
 

# def Test(request):
#  from .models import Village
#  villages = Village.objects.all()
#  data = []
#  with open('readme.txt', 'w') as f:
#   for village in villages:
#    try:
#     vil = TempLinkage.objects.get(village = village.village_name)
#     if vil:
#      pass
#    except:
#     data.append(village.village_name)
#     f.write(village.village_name+"\n")




def get_qr_string(valuee):
 qr = qrcode.QRCode(border=4)
 qrcode_string = valuee
 qr.add_data(qrcode_string)
 qr.make(fit=True)
 img = qr.make_image()
 buffered = io.BytesIO()
 img.save(buffered, format="PNG")
 img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
 return img_str
