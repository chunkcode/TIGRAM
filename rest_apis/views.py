import time

from django.shortcuts import render
from django.db.models import Q
from django.contrib.auth.hashers import make_password
from rest_framework.throttling import UserRateThrottle,AnonRateThrottle
import requests,hashlib
import math, random
# Create your views here.
from django.shortcuts import render
import json
from django.http import JsonResponse
from knox.models import AuthToken
from my_app.models import *
from rest_framework.response import Response
from rest_framework import generics,permissions
from rest_framework.views import APIView
from django.contrib.auth  import login,authenticate,logout
from django.contrib.auth.models import Group
import random
import qrcode
import datetime
import datetime as date
import string
from rest_framework.permissions import IsAuthenticated
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from django.template.loader import get_template
from django.template.loader import render_to_string
from django.conf import settings
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.contrib.staticfiles import finders
from xhtml2pdf import pisa 
import os
from .serializers import UserSerializer,RegisterSerializer,LoginSerializer
# Create your views here.
from django.shortcuts import render
from .serializers import *
from rest_framework import generics,permissions
from rest_framework.response import Response
from django.contrib.auth.models import Group
from knox.models import AuthToken
from rest_framework.views import APIView
from rest_framework.decorators import api_view,permission_classes
from datetime import datetime
import datetime

from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse,HttpResponseNotFound
from django.db.models.functions import ExtractDay

# Create your views here.
from my_app.models import*
from .serializers import*
from rest_framework import status
from django.db.models.functions import Cast

from django.db.models import Count, Case,Sum, When, CharField,IntegerField,DecimalField,FloatField, F
import base64
import datetime
import requests
import hashlib
from datetime import datetime
from datetime import timedelta

def generate_app_id(uid,app_id): #uid
    # uid=31254
    # date = datetime.date.today()
    date1 = date.today()
    # gno = '0'*(4-len(str(uid)))
    # uid = str(gno)+str(uid)
    applicant_no = 'TG/'+str(date1.year)+'/'+str(date1.month)+'/'+str(uid)+'/'+str(app_id)
    # print("----")
    # print("---gen-")
    # date1 = datetime.date.today()
    # print(user_id)
    applicant_no = applicant_no.replace('-','')
    return applicant_no


def generate_noc_app_id(uid,app_id): #uid
    # uid=31254
    # date = datetime.date.today()
    date1 = date.today()
    # gno = '0'*(4-len(str(uid)))
    # uid = str(gno)+str(uid)
    applicant_no = 'NOC/'+str(date1.year)+'/'+str(date1.month)+'/'+str(uid)+'/'+str(app_id)
    # print("----")
    # print("---gen-")
    # date1 = datetime.date.today()
    # print(user_id)
    applicant_no = applicant_no.replace('-','')
    return applicant_no


#UserIDGeneration
def generate_user_id(uid): #uid
    # uid=31254
    date1 = date.today()
    gno = '0'*(4-len(str(uid)))
    uid = str(gno)+str(uid)
    user_id = str(date1)+uid
    # print(user_id)
    user_id = user_id.replace('-','')
    return user_id

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

            # make sure that file exists
            if not os.path.isfile(path):
                    raise Exception(
                            'media URI must start with %s or %s' % (sUrl, mUrl)
                    )
            return path

from rest_framework.throttling import AnonRateThrottle

class AnonTenPerTenMinutesThrottle(AnonRateThrottle):
    rate = '1/s' 
    def parse_rate(self, rate):
      
        return (5, 300) 
class NewLogin(APIView):
    permission_classes = [permissions.AllowAny,]

    throttle_classes = [AnonTenPerTenMinutesThrottle]

    def post(self, request):
        print(request.data)
        username = request.data["email_or_phone"]
        password = request.data["password"]
        error = "error"
        from datetime import datetime
        # token, created = Token.objects.get_or_create(user=user)
        if '@' in username:
            user = authenticate(request,email=username,password=password)
            if user:
                user.auth_token_set.all().delete()
                _, token = AuthToken.objects.create(user)
                CustomUser.objects.filter(id=user.id).update(login_date=datetime.now())

                status = CustomUser.objects.filter(id=user.id)
                data = UserSerializer(user).data
                groups=user.groups.values_list('name',flat = True)
                print(groups)
                print(user)
                rlist = []
                data["user_group"] = groups
                if "division officer" in groups:
                    grp = groups[0]
                    div = DivisionOfficerdetail.objects.filter(div_user_id = user.id).values('id','division_name__name','division_name__id')
                    print(div)
                    rng = Range.objects.filter(division_id = div[0]["division_name__id"]).values('name')
                    data["division"] =  div
                    
                    for i in rng:
                        rlist.append(i["name"])

                    data["range"] = rlist
                
                
                if "forest range officer" in groups:
                    grp = groups[0]
                    div = ForestOfficerdetail.objects.filter(fod_user_id = user.id).values('id','range_name_id')
                    fod_list = ForestOfficerdetail.objects.filter(range_name_id=div[0]["range_name_id"]).values_list('fod_user_id',flat=True)
                    range_officer = CustomUser.objects.filter(is_delete=False,groups__name='deputy range officer',id__in=fod_list).values_list('id','name')
                    data["range"] = range_officer
                if "state officer" in groups:
                    div = StateOfficerdetail.objects.filter(state_user_id = user.id).values('id','state_name')
                    #print(div,"*************************")
                    temp = []
                   
                    if div:
                        div_list = Division.objects.filter(state__name =div[0]["state_name"]).values('id','name')
                        print(div_list)
                        for k in div_list:
                            trp ={}
                 #            
                            trp["division"] = k["name"]
                            rangelst = []
                            arlt = Range.objects.filter(division_id = k["id"]).values_list('name',flat=True)
                            trp["ranges"] =arlt#list(arlt)
                            temp.append(trp)
                            
                          
                        
                    #rng = Range.objects.filter(division_id = div[0]["division_name__id"]).values('name')
                    data["division_range_list"] =  temp
                    
                   # for i in rng:
                    #    rlist.append(i["name"])

                    #data["range"] = rlist
                  
                  
                  
                  
                #img = data["profile_pic"]
                #del data["profile_pic"]

                #if img =="":
                #    data["profile_pic"]  = settings.SERVER_BASE_URL+settings.NO_PROFILE_PATH+img
                #else:
                #    data["profile_pic"]  = settings.SERVER_BASE_URL+settings.PROFILE_PATH+img
                #print(settings.SERVER_BASE_URL+settings.NO_PROFILE_PATH+img)


                content= {
                    "status":"success",
                    "message":"Successfully Login",
                    "data":data,
                    "token":token
                    }
            else:
                content = {
                    "status":"error",
                    "message":"Invalid Credentials"

                }



                # print("email")
        else:
            print("phone")
            eml=""
            em = CustomUser.objects.filter(phone=username).values('email')
            if em:

                print(em[0]["email"])
                eml= em[0]["email"]
            else:
                eml=""
            user = authenticate(email=eml,password=password)
            if user:
                user.auth_token_set.all().delete()
                _, token = AuthToken.objects.create(user)
                CustomUser.objects.filter(id=user.id).update(login_date=datetime.now())

                status = CustomUser.objects.filter(id=user.id)
                data = UserSerializer(user).data
                print(data,"dataaaaaaaaaaaaaaaaaaaaaaaaaaa")
                groups=user.groups.values_list('name',flat = True)
                print(groups)
                data["user_group"] = groups
                #img = data["profile_pic"]
                #del data["profile_pic"]

                #if img =="":
                #    data["profile_pic"]  = settings.SERVER_BASE_URL+settings.NO_PROFILE_PATH+img
                #else:
                #    data["profile_pic"]  = settings.SERVER_BASE_URL+settings.PROFILE_PATH+img
                #print(settings.SERVER_BASE_URL+settings.NO_PROFILE_PATH+img)

    
                content= {
                    "status":"success",
                    "message":"Successfully Login",
                    "data":data,
                    "token":token
                    }
            else:
                content = {
                    "status":"error",
                    "message":"Invalid Credentials"

                }

        return Response(content)

class LoginAPI(generics.GenericAPIView):
    serializer_class = LoginSerializer
    throttle_classes = [AnonTenPerTenMinutesThrottle]
    def post(self,request,*args,**kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            customuser = serializer.validated_data
            customuser.auth_token_set.all().delete()
            _, token = AuthToken.objects.create(customuser)
            CustomUser.objects.filter(id=customuser.id,mobile_verified = "True").update(login_date=datetime.now())

            status = CustomUser.objects.filter(id=customuser.id)
            print(status)

            data = UserSerializer(customuser,context=self.get_serializer_context()).data
            groups=customuser.groups.values_list('name',flat = True)
            print(groups)
            data["user_group"] = groups
            img = data["profile_pic"]
            del data["profile_pic"]

            if img =="":
                data["profile_pic"]  = settings.SERVER_BASE_URL+settings.NO_PROFILE_PATH+img
            else:
                data["profile_pic"]  = settings.SERVER_BASE_URL+settings.PROFILE_PATH+img
            print(settings.SERVER_BASE_URL+settings.NO_PROFILE_PATH+img)

   
            return Response({
                "data":data,
                "token":token
                })
        else:
            print(serializer)
            print(serializer.errors)

            return Response({
                "Login":"Denied",
                })



class NewRegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = []
    def post(self,request,*args,**kwargs):

        user_type = "user"
        # name = request.data.pop("name")
        # phone = request.data.pop("phone")
        # email = request.data.pop("email")
        # password = request.data.pop("password")
        # address = request.data.pop("address")
        # photo_proof_name = request.data.pop("photo_proof_name")
        # photo_proof_img = request.data.pop("photo_proof_img")
        # photo_proof_type_id = request.data.pop("photo_proof_img")
        photo_proof_img = request.data.pop("photo_proof_img")
        print(request.data)
        phone = request.data["phone"]
        ph_exists = CustomUser.objects.filter(phone = phone)
        if ph_exists:
            
            return Response({
                "status":"Error",
                "Message":"Phone Number Already Exists."
                })
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            customuser = serializer.save()
          
            group = Group.objects.get(name=user_type)
            group.user_set.add(customuser)
                        
            otp = ''.join(random.sample("0123456789", 4))
            if photo_proof_img !="":
                generated_id = generate_user_id(customuser.id)
                customuser.user_id = generated_id
                make_id = str(customuser.id)+'r' 
                url = '/static/media/upload/'
                saved_photo=upload_product_image_file(customuser.id,photo_proof_img,url,'PhotoProof')
                customuser.photo_proof_img = saved_photo
                CustomUser.objects.filter(id=customuser.id).update(photo_proof_img=settings.SERVER_BASE_URL + settings.PHOTO_PROOF_PATH+saved_photo)
                print(saved_photo)
                # pf_name = save_img(photo_proof_img,customuser.id)
                # pf_name = settings.SERVER_BASE_URL+settings.PHOTO_PROOF_PATH+pf_name
            else:

                pf_name = settings.SERVER_BASE_URL+settings.NO_IMAGE
            message ="sent"
            send_status = "sent"
            random_otp = "0000"
            otp ="0000"
            # message,send_status,random_otp=send_msg_otp_signup_verification(customuser.phone,customuser.name,otp)
            # status = email(customuser.email,customuser.name,otp)
            # print('Email OTP Status: ',status)
            print('OTP Status ')
            print(send_status)
            # save_otp = SendOtp.objects.create(otp_owner=customuser,otp=otp)
            # save_otp.save()
            data = UserSerializer(customuser,context=self.get_serializer_context()).data
            data["user_type"]=user_type
            # data["profile_image"] = pf_name
            data["photo_proof_img"] = settings.SERVER_BASE_URL + settings.PHOTO_PROOF_PATH+data["photo_proof_img"]
            if send_status !="sent":

                CustomUser.objects.filter(id=customuser.id).delete()

                return Response({
                    "status":"Error",
                    "Message":"Invalid Mobile Number",
                    })
            else:


                return Response({
                    "status":"Success",
                    "Message":"Successfully Registered ",
                    "user":data,
                    
                    })
        else:
            # CustomUser.objects.filter(id=customuser.id).delete()

            print(serializer)
            print(serializer.errors)
            return Response({
                "SignUp":"Denied",
                })



class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    # permission_classes = [permissions.IsAuthenticated,]
    def post(self,request,*args,**kwargs):
        user_type = request.data.pop("user_type")
        # profile_img = request.data.pop("profile_pic")
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            customuser = serializer.save()
          
            group = Group.objects.get(name=user_type)
            group.user_set.add(customuser)
                        
            otp = ''.join(random.sample("0123456789", 4))
            # if profile_img !="":
            #     pf_name = sav_img(profile_img,customuser.id)
            #     pf_name = settings.BASE_URL+settings.PROFILE_IMAGE_URL+pf_name
            # else:

            #     pf_name = settings.BASE_URL+settings.NO_PROFILE_IMAGE_URL
            message ="sent"
            send_status = "sent"
            random_otp = "0000"
            otp ="0000"
            # message,send_status,random_otp=send_msg_otp_signup_verification(customuser.phone,customuser.name,otp)
            # status = email(customuser.email,customuser.name,otp)
            # print('Email OTP Status: ',status)
            print('OTP Status ')
            print(send_status)
            # save_otp = SendOtp.objects.create(otp_owner=customuser,otp=otp)
            # save_otp.save()
            data = UserSerializer(customuser,context=self.get_serializer_context()).data
            data["user_type"]=user_type
            # data["profile_image"] = pf_name
            if send_status !="sent":

                CustomUser.objects.filter(id=customuser.id).delete()

                return Response({
                    "status":"Error",
                    "Message":"Invalid Mobile Number",
                    })
            else:


                return Response({
                    "status":"Success",
                    "Message":"Successfully Registered and waiting for OTP Verification",
                    "user":data,
                    
                    })
        else:
            print(serializer)
            print(serializer.errors)
            return Response({
                "SignUp":"Denied",
                })



class OtpVerify(APIView):
    # Allow any user (authenticated or not) to access this url 
    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):    
        
        email = ''
        user_id = 0
        token = ""
        otp =""
        if not request.data:
            validation_message = 'Please provide email'
            return JsonResponse({'status': 'error', 'message': validation_message} , safe=False)

        if 'email' in request.data and request.data["email"]=="":
            validation_message = "Please Enter Valid Email"
            return JsonResponse({'status': 'error', 'message': validation_message} , safe=False)

        if 'user_id' in request.data:
            user_id = request.data["user_id"]
        
        if 'otp' in request.data:
            otp = request.data["otp"]


        # email = request.data['email']
        # user_exists = SendOtp.objects.filter(otp_owner_id=user_id, otp=otp)
        user_exists = True
        if user_exists:
            
            temp = user_exists[0].otp_owner
            print(temp)
            user_exists.update(otp_verified=True,otp="")
            temp.auth_token_set.all().delete()
            _, token = AuthToken.objects.create(temp)
            validation_status = 'Success'
            validation_message = 'Successfully Verified Your email Address'
            CustomUser.objects.filter(id=user_id).update(user_verified = True)
            print(token)
            return JsonResponse({'status': validation_status, 'message': validation_message,"token":token} , safe=False)

        else:
            validation_status = 'Error'
            validation_message = 'Invalid OTP'
            return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)


def post_to_url(url, data):
    fields = ''
    for key, value in data.items():
        fields += key + '=' + value + '&'
    fields = fields[:-1] # remove the trailing '&'

    response = requests.post(url, data=fields)
    result = response.text
    print(result)

    errors = response.raise_for_status()
    print(errors)

    response_code = response.status_code
    print(response_code)

    return result

def sendSingleSMS(username, encryp_password, senderid, message, mobileno,templateid, deptSecureKey):
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
class ForgotPassword(APIView):
    # Allow any user (authenticated or not) to access this url 
    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):

        email = request.data["username"]
        mobile = request.data["phone"]
       
        data = CustomUser.objects.filter(phone=mobile,email=email)
        if data:
            current_time = datetime.now()
            otp = new_otp_generateOTP()
            print(current_time, 'current_time')
            CustomUser.objects.filter(email=email, phone=mobile).update(forgot_code=otp,
                                                                       no_of_attempts_forgot='0',
                                                                       forgot_otp_created_at=current_time)
            
            USERNAME = "KERALAFOREST-KFDSER"
            PASSWORD = "Fmis@2021"
            SENDERID = "KFDSER"
            KEY = "98a52a38-b8fe-42c8-8fa7-60ba10fc5cbc"
            content = "KeralaForestDept - OTP for resetting your password for "+str(email)+" is "+str(otp)+"."
            
            templateid = "1407169907490040278"
            key = KEY
            message = "KeralaForestDept - OTP for resetting your password for "+"account"+str(email)+" is "+str(otp)+"."
            if otp_check_brute(mobile) == False:
             return JsonResponse({'status': 'success', 'applications':'Exceded daily limit'}, safe=False)
            new_sendSingleSMS(USERNAME, PASSWORD, SENDERID, message, mobile, templateid, key)
            validation_message = 'Success'
            return JsonResponse({'status': 'success', 'message': validation_message} , safe=False)
        validation_message = 'Please try again or Please verify your registered email or phone number with admin'
        return JsonResponse({'status': 'error', 'message': validation_message}, safe=False)
        # return JsonResponse({'status': validation_status, 'message': validation_message,"data":data} , safe=False)



class ForgotOtpVerify(APIView):
    # Allow any user (authenticated or not) to access this url 
    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):
        phone = request.data["phone"]
        otp = request.data["otp"]
        user_Exist = CustomUser.objects.filter(phone=phone, forgot_code=otp)
        if user_Exist:
            data = CustomUser.objects.get(phone=phone, forgot_code=otp)
            db_time = data.forgot_otp_created_at
            datetime_obj = datetime.strptime(db_time, '%Y-%m-%d %H:%M:%S.%f')
            print(type(datetime_obj), 'datetime_obj')
            print(datetime_obj, 'datetime_obj')
            now = datetime.now()
            print(now, 'now')
            print(type(now), "now")
            time_difference = now - datetime_obj
            if time_difference > timedelta(minutes=3):
                validation_status = 'Success'
                validation_message = 'Otp expired'
                return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)
            else:
                validation_status = 'Success'
                # validation_message = 'Successfully Verified Your Otp'
                return JsonResponse({'status': validation_status}, safe=False)

        else:
            user_Existt = CustomUser.objects.get(phone=phone)
            print(user_Existt, 'user_Existt')
            attempts = user_Existt.no_of_attempts_forgot
            val = int(attempts)
            val = val + 1
            CustomUser.objects.filter(phone=phone).update(no_of_attempts_forgot=val)
            if val > 3:
                message = "You execeded the limit please try after sometime"
                return JsonResponse({'status': 'error', 'message': message}, safe=False)
            else:
                message = "Invalid OPT"
                return JsonResponse({'status': 'error', 'message': message}, safe=False)

class ChangeForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny,]
    def post(self, request):
        phone = request.data["phone"]
        passwd = request.data['passwd']
        passwd1 = request.data['passwd1']
        isuser = CustomUser.objects.filter(phone=phone)
        if passwd == passwd1:
            if isuser:
                # isuser.set_password(passwd)
                new_password = make_password(passwd)
                isuser.update(password=new_password)
                message = "Password Changed Successfully"
                return JsonResponse({'status': 'success', 'message': message}, safe=False)

        else:
            message = "Password not changed"
            print(message)
            return JsonResponse({'status': 'error', 'message': message}, safe=False)


def save_img(img,user_id,image_path,img_type):
    # image_path = settings.QUERY_IMAGE_URL
    # print(img)
    file = img["type"].split('.')
    # file_name = file[0]          
    file_ext = file[1]


    save_img_name = str(img_type)+"_"+str(user_id)+"."+str(file_ext)
                    
    imagefile = str(image_path)+str(save_img_name)

    # dt =  img["image"].split(",")
    imgstring = img["image"]
    imgstring = imgstring.split(',')
    print(imgstring,"*********************8")
    print("*********************8")
    import base64
    imgdata = base64.b64decode(imgstring[1])

    with open(imagefile, 'wb+') as f:

        f.write(imgdata)
    return settings.BASE_URL+image_path+save_img_name







# def upload

# def upload_product_image_file(record_id, post_image, image_path, image_tag):
#   image_name = ''
#   image_path = settings.PROOF_OF_OWNERSHIP_PATH
#   image_path = IMAGE_TAG[image_tag]
#   if not os.path.exists(image_path):
#       os.makedirs(image_path)
#   image_name = None

#   if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
#         file_name = post_image["type"].split('.')
#         file_ext = file_name[1]
#         image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
#         imagefile = str(image_path)+str(image_name)
#         imgstring = post_image["image"]
#         # imgstring = post_image["image"]
#         imgstring = imgstring.split(',')
#         print(imgstring,"*********************8")
#         print("*********************8")
#         import base64
#         imgdata = base64.b64decode(imgstring[1])

#         with open(imagefile, 'wb+') as f:
#         f.write(imgdata)

        
#   return image_name


# def upload


# def upload
IMAGE_TAG = {'AadharCard':settings.AADHAR_IMAGE_PATH,'Declaration':settings.DECLARATION_PATH,
            'License':settings.LICENSE_PATH,'LocationSketch':settings.LOCATION_SKETCH_PATH,
            'ProofOfOwnership':settings.PROOF_OF_OWNERSHIP_PATH,'RevenueApplication':settings.REVENUE_APPLICATION_PATH,
            'RevenueApproval':settings.REVENUE_APPROVAL_PATH,'TreeOwnership':settings.TREE_OWNERSHIP_PATH,
            'Signature':settings.SIGN_PATH,'QRCode' :settings.QRCODE_PATH,'Profile':settings.PROFILE_PATH,
            'PhotoProof':settings.PHOTO_PROOF_PATH,'Location_img1':settings.LOCATION_IMAG1,'Location_img2':settings.LOCATION_IMAG2,
            'Location_img3':settings.LOCATION_IMAG3,'Location_img4':settings.LOCATION_IMAG4,'TimberImage':settings.TIMBER_IMAGE


    }


def upload_product_image_file(record_id, post_image, image_path, image_tag):
    image_name = ''
    image_path = settings.PROOF_OF_OWNERSHIP_PATH
    image_path = IMAGE_TAG[image_tag]
    if not os.path.exists(image_path):
        os.makedirs(image_path)
    image_name = None
    if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
        # try:
        filename = post_image["type"]
        # print(filename,'file_name')
        file_ext = filename
        # print("")

        image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
        imagefile = str(image_path)+str(image_name)
        imgstring = post_image["image"]
        imgstring1 = imgstring.split(',')
        # print(imgstring,'imagestring value')


        imgdata = base64.b64decode(imgstring)
        with open(imagefile, 'wb+') as f:
            f.write(imgdata)

    return image_name



def form_three_upload_product_image_file(record_id, post_image, image_path, image_tag):
    image_name = ''
    image_path = settings.FORM_THREE_FOREST_SIGN
    image_path = IMAGE_TAG[image_tag]
    if not os.path.exists(image_path):
        os.makedirs(image_path)
    image_name = None
    if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
        # try:
        filename = post_image["type"]
        file_ext = filename


        image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
        imagefile = str(image_path)+str(image_name)
        imgstring = post_image["image"]
        imgstring1 = imgstring.split(',')
        import base64
        imgdata = base64.b64decode(imgstring)
        with open(imagefile, 'wb+') as f:
            f.write(imgdata)



    return image_name





def upload_photo_edit_image_file(record_id, post_image, image_path, image_tag):
    image_name = ''
    #image_path = settings.PROOF_OF_OWNERSHIP_PATH
    image_path = IMAGE_TAG[image_tag]
    if not os.path.exists(image_path):
        os.makedirs(image_path)
    image_name = None
    if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
        # try:
        filename = post_image["type"].split('.')
        file_ext = filename[1]
        print("")

        image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
        imagefile = str(image_path)+str(image_name)
        imgstring = post_image["image"]
        imgstring1 = imgstring.split(',')

        imgdata = base64.b64decode(imgstring)
        with open(imagefile, 'wb+') as f:
            f.write(imgdata)



    return image_name

def timber_image_file(record_id, post_image, image_path, image_tag):
    image_name = ''
    image_path = settings.TIMBER_IMAGE
    image_path = IMAGE_TAG[image_tag]
    print(image_path,'image_path')
    if not os.path.exists(image_path):
        os.makedirs(image_path)
    image_name = None
    if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
        # try:
        filename = post_image["type"]
        print(filename,'filename')
        file_ext = filename
        print(file_ext,'file_ext')
        image_name =image_tag+"_"+str(record_id)+"_image_"+str(int(time.time()))+str(file_ext)
        print(image_name,"image_name")
        imagefile = str(image_path)+str(image_name)
        imgstring = post_image["image"]

        imgstring1 = imgstring.split(',')
        import base64
        imgdata = base64.b64decode(imgstring)
        with open(imagefile, 'wb+') as f:
            f.write(imgdata)
    return image_name





# def upload_product_image_file(record_id, post_image, image_path, image_tag):
#   image_name = ''
#   image_path = settings.PROOF_OF_OWNERSHIP_PATH
#   image_path = IMAGE_TAG[image_tag]
#   if not os.path.exists(image_path):
#       os.makedirs(image_path)
#   image_name = None
#   # j=random.randint(0,1000)
#   if post_image != '' and image_path != '' and image_tag != '' and record_id > 0:
#       try:
#           filename = post_image["type"].split('.')
#           file_ext = filename[1]
#             print("")
#           # arr_len = len(filearr)

#           # if len(filearr) > 1 :
#           #   file_name = filearr[0]          
#           #   file_ext = filearr[arr_len-1]
#               #----------------------------------------#

#             # image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
#             # imagefile = str(image_path)+str(image_name)
#             # with open(imagefile, 'wb+') as destination:
#             #     print(post_image.chunks(),"---====--",destination)
#             #     for chunk in post_image.chunks():
#             #         print(destination,'----==')
#             #         destination.write(chunk)
#       except Exception as Error:
#           print("----here",Error)
#           pass
            
#   return image_name
class UpdateTimberlog(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        application=request.data['app_id']
        log_details=request.data['log_details']
        validation_status = ''
        validation_message = ''
        if log_details!="" or application!="" :
            tlog_exist = Timberlogdetails.objects.filter(appform_id=application)
            if tlog_exist:
                tlog_exist.delete()
            # else:

            try:
                tlog=[]
                 # pass
                for i in log_details:
                    print(i)

                    timber = Timberlogdetails(appform_id=application,species_of_tree=i["species_of_tree"], 
                    length=i["length"], breadth=i["breadth"],volume=i["volume"],latitude=i["latitude"],longitude=i["longitude"])
                    tlog.append(timber)
                Timberlogdetails.objects.bulk_create(tlog)
                groups=request.user.groups.values_list('name',flat = True)
                if groups[0] =='user':
                  Applicationform.objects.filter(id=application).update(log_updated_by_user=True)
                validation_status = 'Success'
                validation_message = 'Log Details Updated Successfully.'
            except Exception as e:
                print(e,'Error')
                validation_status = 'Fail'
                validation_message = 'Log Details have not been updated successfully.' 
        else:
            validation_status = 'Fail'
            validation_message = 'Log Details have not been updated successfully.'

           
        print(self.request.user.id)        
        return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)
        # return JsonResponse({'message':'Updated successfully!!!','timber_log':list(timber_log)})




class InsertRecord(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated]
 
    def post(self, request):

        name = ""
        address = ""
        survey_number = ""
        num_trees_proposed_cut = ""
        village = ""
        taluka = ""
        block = ""
        district = ""
        proof_of_ownership_img = ""
        species_of_tree  = ""
        purpose = ""
        log_details = ""
        revenue_application = ""
        revenue_approval = ""
        declaration = ""
        location_sktech = ""
        tree_ownership_detail = ""
        photo_id_proof = "" 
        photo_id_proof_img = "" 
        destination_details = "" 
        vehicle_reg_no = "" 
        driver_name = "" 
        driver_phone = "" 
        mode_of_transport = "" 
        license_image = "" 
        signature_img = "" 

        validation_status = 'error'
        validation_message = 'Error'
        name=request.data["name"]
        address=request.data["address"]
        survey_no=request.data["survey_no"]
        tree_proposed=request.data["tree_proposed"]
        village=request.data["village"]
        district=request.data["district"]
        block=request.data["block"]
        taluka=request.data["taluka"]
        division=request.data["division"]
        area_range=request.data["area_range"]
        pincode=request.data["pincode"]
        # print(request.FILES)
        ownership_proof_img=request.data["ownership_proof_img"]
        revenue_application_img=request.data["revenue_application_img"]
        revenue_approval_img=request.data["revenue_approval_img"]
        declaration_img=request.data["declaration_img"]
        location_sketch_img=request.data["location_sketch_img"]
        tree_ownership_img=request.data["tree_ownership_img"]
        aadhar_card_img=request.data["aadhar_card_img"]
        signature_img = request.data["signature_img"]
        lic_img=request.data["licence_img"]
        tree_species=request.data["tree_species"]
        purpose = request.data["purpose_cut"]
        veh_reg=request.data["vehicel_reg"]
        driver_name= request.data["driver_name"]
        phone = request.data["phone"]
        mode = request.data["mode"]
        log_details = request.data["log_details"]
        trees_cutted = request.data["trees_cutted"]
        destination_address = request.data["destination_address"]
        print("___________________________")
        url='static/media/'
        application = Applicationform.objects.create(
            name=name,address=address,destination_details=destination_address,
            survey_no=survey_no,village=village,total_trees=tree_proposed,
            district=district,species_of_trees=tree_species,pincode=pincode,
            purpose=purpose,block=block,taluka=taluka,division=division,
            area_range=area_range,by_user=request.user
            )
        print(application)
        saved_image=upload_product_image_file(application.id,aadhar_card_img,url,'AadharCard')
        saved_image_2=upload_product_image_file(application.id,revenue_approval_img,url,'RevenueApproval')
        saved_image_1=upload_product_image_file(application.id,declaration_img,url,'Declaration')
        saved_image_3=upload_product_image_file(application.id,revenue_application_img,url,'RevenueApplication')
        saved_image_4=upload_product_image_file(application.id,location_sketch_img,url,'LocationSketch')
        saved_image_5=upload_product_image_file(application.id,tree_ownership_img,url,'TreeOwnership')
        saved_image_6=upload_product_image_file(application.id,ownership_proof_img,url,'ProofOfOwnership')
        # saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')
        saved_image_8=upload_product_image_file(application.id,signature_img,url,'Signature')
        application.proof_of_ownership_of_tree=saved_image_6

                
        image_doc=image_documents.objects.create(app_form=application,
                revenue_approval=saved_image_2,declaration=saved_image_1,
                revenue_application=saved_image_3,location_sktech=saved_image_4,
                tree_ownership_detail=saved_image_5,aadhar_detail=saved_image,
                signature_img=saved_image_8
            )
        application.revenue_approval = True
        application.declaration = True
        uid=request.user.id
        
        application.application_no=generate_app_id(uid,application.id)
 #       application_no=generate_app_id(uid,application.id)
        #clprint(application_no,"*******************")
        application.signature_img = True
        application.revenue_application = True
        application.location_sktech = True
        application.tree_ownership_detail = True
        application.aadhar_detail = True
#        tem = Applicationform.objects.filter(id = application.id).update(application_no=application_no,signature_img = True,revenue_application = True,location_sktech = True,tree_ownership_detail = True,aadhar_detail = True)
        application.trees_cutted = True
        #print(")s",tem)
        tlog =[]
        application.trees_cutted= True

        if log_details!="" : 
            for i in log_details:
                print(i)

                timber = Timberlogdetails(appform=application,species_of_tree=i["species_of_tree"], 
                length=i["length"], breadth=i["breadth"],volume=i["volume"],latitude=i["latitude"],longitude=i["longitude"])
                tlog.append(timber)
            Timberlogdetails.objects.bulk_create(tlog)
        application.save()
        saved_image_7 =""
        if lic_img!="":
            saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')

        vehicle = Vehicle_detials.objects.create(app_form=application,
            license_image=saved_image_7,vehicle_reg_no=veh_reg,
            driver_name=driver_name,driver_phone=phone,
            mode_of_transport=mode
            )
        validation_status = 'Success'
        validation_message = 'Data Saved Successfully.'   
        print(self.request.user.id)        
        return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)


class NewInsertRecord(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):

        name = ""
        address = ""
        survey_number = ""
        num_trees_proposed_cut = ""
        village = ""
        taluka = ""
        block = ""
        district = ""
        proof_of_ownership_img = ""
        species_of_tree = ""
        purpose = ""
        log_details = ""
        revenue_application = ""
        revenue_approval = ""
        declaration = ""
        location_sktech = ""
        tree_ownership_detail = ""
        photo_id_proof = ""
        photo_id_proof_img = ""
        destination_details = ""
        vehicle_reg_no = ""
        driver_name = ""
        driver_phone = ""
        mode_of_transport = ""
        license_image = ""
        signature_img = ""
        location_img1 = ""
        location_img2 = ""
        location_img3 = ""
        location_img4 = ""
        image1_lat = ""
        image2_lat = ""
        image3_lat = ""
        image4_lat = ""
        image1_log = ""
        image2_log = ""
        image3_log = ""
        image4_log = ""

        validation_status = 'error'
        validation_message = 'Error'
        name = request.data["name"]
        address = request.data["address"]
        survey_no = request.data["survey_no"]

        tree_proposed = request.data["tree_proposed"]
        village = request.data["village"]
        district = request.data["district"]
        block = request.data["block"]
        taluka = request.data["taluka"]
        division = request.data["division"]
        area_range = request.data["area_range"]
        pincode = request.data["pincode"]
        # print('before image')
        # # print(request.FILES)
        ownership_proof_img = request.data["ownership_proof_img"]
        # print('after image')
        revenue_application_img = request.data["revenue_application_img"]
        revenue_approval_img = request.data["revenue_approval_img"]
        declaration_img = request.data["declaration_img"]
        location_sketch_img = request.data["location_sketch_img"]
        tree_ownership_img = request.data["tree_ownership_img"]
        aadhar_card_img = request.data["aadhar_card_img"]
        signature_img = request.data["signature_img"]
        lic_img = request.data["licence_img"]
        tree_species = request.data["tree_species"]
        purpose = request.data["purpose_cut"]
        veh_reg = request.data["vehicel_reg"]
        driver_name = request.data["driver_name"]
        phone = request.data["phone"]
        mode = request.data["mode"]
        log_details = request.data["log_details"]
        trees_cutted = request.data["trees_cutted"]
        destination_address = request.data["destination_address"]
        destination_state = request.data["destination_state"]
        location_img1 = request.data["location_img1"]
        location_img2 = request.data["location_img2"]
        location_img3 = request.data["location_img3"]
        location_img4 = request.data["location_img4"]
        image1_lat = request.data["image1_lat"]
        image2_lat = request.data["image2_lat"]
        image3_lat = request.data["image3_lat"]
        image4_lat = request.data["image4_lat"]
        image1_log = request.data["image1_log"]
        image2_log = request.data["image2_log"]
        image3_log = request.data["image3_log"]
        image4_log = request.data["image4_log"]
        rangedetails = Range.objects.get(name=area_range)
        id2 = rangedetails.id
        revenue = RevenueOfficerdetail.objects.get(range_name_id=id2)

        revenueid = revenue.Rev_user_id
        #
        # print("___________________________")
        url = 'static/media/'
        application = Applicationform.objects.create(
            name=name, address=address, destination_details=destination_address, destination_state=destination_state,
            survey_no=survey_no, village=village, total_trees=tree_proposed,
            district=district, species_of_trees=tree_species, pincode=pincode,
            purpose=purpose, block=block, taluka=taluka, division=division,
            area_range=area_range, by_user=request.user,assgn_deputy='assgned'
        )
        # print(application)
        saved_image = upload_product_image_file(application.id, aadhar_card_img, url, 'AadharCard')
        saved_image_2 = upload_product_image_file(application.id, revenue_approval_img, url, 'RevenueApproval')
        saved_image_1 = upload_product_image_file(application.id, declaration_img, url, 'Declaration')
        saved_image_3 = upload_product_image_file(application.id, revenue_application_img, url, 'RevenueApplication')
        saved_image_4 = upload_product_image_file(application.id, location_sketch_img, url, 'LocationSketch')
        saved_image_5 = upload_product_image_file(application.id, tree_ownership_img, url, 'TreeOwnership')
        saved_image_6 = upload_product_image_file(application.id, ownership_proof_img, url, 'ProofOfOwnership')
        # saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')
        saved_image_8 = upload_product_image_file(application.id, signature_img, url, 'Signature')
        saved_image_9 = upload_product_image_file(application.id, location_img1, url, 'Location_img1')
        saved_image_10 = upload_product_image_file(application.id, location_img2, url, 'Location_img2')
        saved_image_11 = upload_product_image_file(application.id, location_img3, url, 'Location_img3')
        saved_image_12 = upload_product_image_file(application.id, location_img4, url, 'Location_img4')
        application.proof_of_ownership_of_tree = saved_image_6

        image_doc = image_documents.objects.create(app_form=application,
                                                   revenue_approval=saved_image_2, declaration=saved_image_1,
                                                   revenue_application=saved_image_3, location_sktech=saved_image_4,
                                                   tree_ownership_detail=saved_image_5, aadhar_detail=saved_image,
                                                   signature_img=saved_image_8,location_img1=saved_image_9,location_img2=saved_image_10,location_img3=saved_image_11,
                                                 location_img4=saved_image_12,image1_lat=image1_lat,image2_lat=image2_lat,image3_lat=image3_lat,
                                                 image4_lat=image4_lat,image1_log=image1_log,image2_log=image2_log, image3_log= image3_log, image4_log=image4_log
                                                   )
        # application.revenue_approval = True
        # application.declaration = True
        application.verify_office = True
        application.application_status = 'P'
        application.reason_office = 'Recommended'
        application.approved_by_revenue_id = revenueid
        uid = request.user.id
        if destination_state != "Kerala":
            application.other_state = True
            # application.is_form_two = True

        application.application_no = generate_app_id(uid, application.id)
        #       application_no=generate_app_id(uid,application.id)
        # clprint(application_no,"*******************")
        application.signature_img = True
        application.revenue_application = True
        application.location_sktech = True
        application.tree_ownership_detail = True
        application.aadhar_detail = True
        #        tem = Applicationform.objects.filter(id = application.id).update(application_no=application_no,signature_img = True,revenue_application = True,location_sktech = True,tree_ownership_detail = True,aadhar_detail = True)
        #         application.trees_cutted = True
        # print(")s",tem)
        tlog = []
        application.trees_cutted = True
        #
        if log_details != "":
            for i in log_details:
                print(i)

                timber = Timberlogdetails(appform=application, species_of_tree=i["species_of_tree"],
                                          length=i["length"], breadth=i["breadth"], volume=i["volume"],
                                          latitude=i["latitude"], longitude=i["longitude"])
                tlog.append(timber)
            Timberlogdetails.objects.bulk_create(tlog)
        application.save()
        saved_image_7 = ""
        if lic_img != "":
            saved_image_7 = upload_product_image_file(application.id, lic_img, url, 'License')
        #
        vehicle = Vehicle_detials.objects.create(app_form=application, vehicle_reg_no=veh_reg,
                                                 driver_name=driver_name, driver_phone=phone,
                                                 mode_of_transport=mode,license_image=saved_image_7
                                                 )
        validation_status = 'Success'
        validation_message = 'Data Saved Successfully.'
        # print(self.request.user.id)
        return JsonResponse({'status': validation_status, 'message': validation_message}, safe=False)


class ListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        application_detail = list(Applicationform.objects.filter(by_user_id=self.request.user.id,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)


class ListAddImageApplication(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):
        application_detail = list(
            Applicationform.objects.filter(by_user_id=self.request.user.id, application_status='I').values().annotate(
                assigned_deputy1_name=F('assigned_deputy1_id__name'),
                assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message, 'data': application_detail},
                            safe=False)
        


class ListDistrict(APIView):

    permission_classes = [permissions.AllowAny,]
 
    def get(self, request):

        application_detail = list(District.objects.all().values('district_name'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)

class LoadTaluka(APIView):

    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):
        district = request.data['district']
        application_detail = list(Taluka.objects.filter(dist__district_name__iexact=district).values('taluka_name'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False) 

class LoadVillage(APIView):

    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):
        taluka = request.data['taluka']
        application_detail = list(Village.objects.filter(taluka__taluka_name__iexact=taluka).values('village_name'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)       

class LoadDivision(APIView):

    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):
        range_area = request.data['range_area']
        application_detail = list(Range.objects.filter(division__name__iexact=range_area).values('name'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)




class ViewApplication(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
     
        app_id = request.data["app_id"]
        groups=list(request.user.groups.values_list('name',flat = True))
        
        chck_app = Applicationform.objects.filter(id=app_id)
        if chck_app:
            pass
        else:
            validation_status = 'Error'
            validation_message = 'Application Not Found.'   
            return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)

        groups=request.user.groups.values_list('name',flat = True)
        if groups[0] == "user":
         if chck_app[0].by_user == request.user:  
              pass
         else:
             return JsonResponse({'status': 'error', 'message': "unauthorized api request"}, safe=False)
        else:
            pass      
        application_detail = list(Applicationform.objects.filter(id=app_id).values())
         
        if application_detail[0]["proof_of_ownership_of_tree"]!="":
            application_detail[0].update({"proof_of_ownership_of_tree":settings.SERVER_BASE_URL.replace(':8000/','')+settings.PROOF_OF_OWNERSHIP_PATH.replace('/home/ubuntu/timberproject','')+application_detail[0]["proof_of_ownership_of_tree"]})
            # print("*12222222222222222222222222222")

        trees_species_list = list(TreeSpecies.objects.all().values('name'))
        # image_document =""
        # print("********************")
                #         "revenue_approval": "RevenueApproval_94_image.png",
                # "declaration": "Declaration_94_image.png",
                # "revenue_application": "RevenueApplication_94_image.png",
                # "location_sktech": "LocationSketch_94_image.png",
                # "tree_ownership_detail": "TreeOwnership_94_image.png",
                # "aadhar_detail": "AadharCard_94_image.png"

        image_document = list(image_documents.objects.filter(app_form_id=app_id).values())
        t1 = image_document[0]["signature_img"]
        image_document[0].update({"signature_img":settings.SERVER_BASE_URL.replace(':8000/','')+settings.SIGN_PATH.replace('/home/ubuntu/timberproject','')+image_document[0]["signature_img"]})
        image_document[0].update({"declaration":settings.SERVER_BASE_URL.replace(':8000/','')+settings.DECLARATION_PATH.replace('/home/ubuntu/timberproject','') +image_document[0]["declaration"]})
        image_document[0].update({"revenue_approval":settings.SERVER_BASE_URL.replace(':8000/','')+settings.REVENUE_APPROVAL_PATH.replace('/home/ubuntu/timberproject','') +image_document[0]["revenue_approval"]})
        #image_document[0].update({"location_sktech":settings.SERVER_BASE_URL+settings.LOCATION_SKETCH_PATH +image_document[0]["location_sktech"]})
        #image_document[0].update({"tree_ownership_detail":settings.SERVER_BASE_URL+settings.TREE_OWNERSHIP_PATH +image_document[0]["tree_ownership_detail"]})
        image_document[0].update({"aadhar_detail":settings.SERVER_BASE_URL.replace(':8000/','')+settings.AADHAR_IMAGE_PATH.replace('/home/ubuntu/timberproject','')+image_document[0]["aadhar_detail"]})
        #image_document[0].update({"revenue_application":settings.SERVER_BASE_URL+settings.REVENUE_APPLICATION_PATH +image_document[0]["revenue_application"]})
        image_document[0].update({"location_img1": settings.SERVER_BASE_URL.replace(':8000/','') + settings.LOCATION_IMAG1.replace('/home/ubuntu/timberproject','') +image_document[0]["location_img1"]})
        image_document[0].update({"location_img2": settings.SERVER_BASE_URL.replace(':8000/','') + settings.LOCATION_IMAG2.replace('/home/ubuntu/timberproject','')+ image_document[0]["location_img2"]})
        image_document[0].update({"location_img3": settings.SERVER_BASE_URL.replace(':8000/','') + settings.LOCATION_IMAG3.replace('/home/ubuntu/timberproject','') + image_document[0]["location_img3"]})
        image_document[0].update({"location_img4": settings.SERVER_BASE_URL.replace(':8000/','') + settings.LOCATION_IMAG4.replace('/home/ubuntu/timberproject','')+ image_document[0]["location_img4"]})

        # if application_detail:
        vehicle = list(Vehicle_detials.objects.filter(app_form_id=app_id).values())
        #print(vehicle[0],"22222222222222222222222")
        isvehicle=''
        if vehicle:
            vehicle=vehicle[0]
            vehicle.update({"license_image":settings.SERVER_BASE_URL+settings.LICENSE_PATH [-26:]+str(vehicle["license_image"])})
            # vehicle.update({"photo_of_vehicle_with_number":settings.SERVER_BASE_URL+settings.PHOTO_OF_VEHICLE+vehicle["photo_of_vehicle_with_number"]})

            

        else:
            isvehicle = 'Not Applicable'
        is_timberlog=''
        timber_log = Timberlogdetails.objects.filter(appform_id=app_id)
        if timber_log:
            timber_log=list(timber_log.values())
            # for tl in timber_log:
            #     tl.update({"log_qr_code_img":settings.SERVER_BASE_URL+settings.LOG_QR})
        else:
            timber_log = ""
            is_timberlog='N/A'
        print("********************")

        # transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
        transit_pass_exist = False
        # if groups[0] == "revenue officer" and application_detail[0].verify_office == True:
        #     transit_pass_exist = True
        # elif groups[0] == "deputy range officer" and application_detail[0].depty_range_officer == True:
        #     transit_pass_exist = True
        # elif groups[0] == "forest range officer" and application_detail[0].verify_range_officer == True:
        #     transit_pass_exist = True
        # else:
        #     pass
        print(transit_pass_exist,'----TP')
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        print(self.request.user.id)
        species_list = Species_geodetails.objects.filter(appform_id=app_id).values_list('species_tree__name',flat=True)
        species_location = Species_geodetails.objects.filter(appform_id=app_id).values('species_tree__name','latitude','longitude','length','breadth','volume')
        data = {
            'applications':application_detail,'image_documents':image_document,'groups':groups[0],'species_location':list(species_location),
            'transit_pass_exist':transit_pass_exist,'vehicle':vehicle,'timber_log':timber_log,'species_list':list(species_list),
            'trees_species_list':trees_species_list,'isvehicle':isvehicle,'is_timberlog':is_timberlog}
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':data} , safe=False)




def new_transit_pass_pdf(request,applicant_no):
    logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
    logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
    logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
    # image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
    # transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
    # log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
    # signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
    # qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)

    # print(applicant_no,"******************")
    application = Applicationform.objects.filter(id=applicant_no).exclude(transit_pass_id=0)
    # print(application)
    is_vehicle = "NO"
    vdata = {}
    if application:
        import datetime

        if application[0].other_state == False:
            authorizer_name = application[0].approved_by.name if application[0].is_noc==False and application[0].deemed_approval==False else 'N/A' 
        else:
            authorizer_name = application[0].approved_by_division.name if application[0].is_noc==False and application[0].deemed_approval==False else 'N/A'  


        #authorizer_name = application[0].approved_by.name
        application=application.values()

        veh_details = Vehicle_detials.objects.filter(app_form_id = applicant_no)
        if veh_details:
            is_vehicle = "YES"
            vdata = veh_details.values()
        image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
        transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
        log_details = Timberlogdetails.objects.filter(appform_id=applicant_no).values()
        signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
        qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
        date_1 = datetime.datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
        main_url=settings.SERVER_BASE_URL+'static/media/qr_code/'
        # print(application[0]['approved_by_id__name'])\
        # <td style="width :300px !important; text-align: center;font-size: 16px">{{each.species_of_tree}}</td>
  #         <td style="text-align: center;font-size: 16px">{{each.length}}</td>
  #         <td style="text-align: center;font-size: 16px">{{each.breadth}}</td>
  #         <td style="text-align: center;font-size: 16px">{{each.volume}}</td>
        log={}
        # print(log_details.values(),'----')
        for each in log_details:
            each['main_url'] = main_url+each['log_qr_code_img']
            # log['']=
            # log['']=
            # log['']=
            # log['']=

        # print(log_details,'------=')
        expiry_date = date_1 + datetime.timedelta(days=7)
        context = {'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,'main_url':main_url,
            'signature_img':signature_img,'qr_img':qr_img,'authorizer_name':authorizer_name,"is_vehicle":is_vehicle,"vdata":vdata
            ,'transitpass':transitpass,'log_details':log_details,'expiry_date':expiry_date}
        from datetime import datetime

        response = HttpResponse(content_type='application/pdf')
        # datetime.strptime(from_date, "%Y-%m-%d").strftime('%Y-%m-%d')
        # applicant_no.replace('-','')
        today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
        # print(today_stamp,'======',datetime.now())
        filename= 'TransitPass-'+str(application[0]['application_no'])+'-'+today_stamp+''
        response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'
        # find the template and render it.
        template = get_template('pdf_template/newtransitpass_tbl.html')
        html = template.render(context)

        # create a pdf
        pisa_status = pisa.CreatePDF(
            html, dest=response, link_callback=link_callback)
        # if error then show some funy view
        return response
    else:
        print('No Data in Summary')
        return JsonResponse({'status': "error", 'message': "Error"} , safe=False)
# return JsonResponse({'status': "error", 'message': "Error"} , safe=False)

# class new_user_report(APIView):
#     permission_classes = [permissions.IsAuthenticated,]
# @api_view(['post'])
# # @authentication_classes([SessionAuthentication, BasicAuthentication])
# @permission_classes([IsAuthenticated])
def new_user_report(request,applicant_no):
    logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
    logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
    logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
    # groups=request.user.groups.values_list('name',flat = True)
    # pr/int(groups,"*********************")
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
    print('-------------------',logo1,logo2,qr_img,'-----=============')
    # pdf = pdfkit.from_string(wt, False,configuration=config)
    template =''
    # if groups[0] in ['revenue officer','deputy range officer','forest range officer']:
    #     template = get_template("pdf_template/report.html")
    # else:
    # template = get_template("pdf_template/userreport.html")
    application = Applicationform.objects.filter(id=applicant_no).values()
    # print(application)
    if application:
        approved_names = Applicationform.objects.filter(id=applicant_no).values('approved_by_division__name','approved_by_deputy__name','approved_by_revenue__name','approved_by__name')
        import datetime
        date_1 = datetime.datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
        expiry_date = date_1 + datetime.timedelta(days=7)
        context = {'application':application,"logo1":logo1,"logo2":logo2,'expiry_date':expiry_date,"logo3":logo3,
        'qr_img':qr_img,'transitpass':transitpass,'is_transitpass':is_transitpass,'approved_names':list(approved_names)}  # data is the context data that is sent to the html file to render the output. 
        response = HttpResponse(content_type='application/pdf')
        from datetime import datetime
        today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
        # print(today_stamp,'======',datetime.now())
        filename= 'UserReport-'+str(application[0]['application_no'])+'-'+today_stamp+''
        response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'

        
        # response['Content-Disposition'] = 'attachment; filename="UserReport.pdf"'
        # print(context)
        # print(context,"#$$$$$$$###########/")
        template = get_template('pdf_template/newreport.html')
        html = template.render(context)

        # create a pdf
        pisa_status = pisa.CreatePDF(
            html, dest=response, link_callback=link_callback)
        # if error then show some funy view
        return response
    else:
        print('No Data in Summary')
        return JsonResponse({'status': "error", 'message': "Error"} , safe=False)

class EditProfile(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        user_id=request.user.id
        contact = request.data["contact"]
        name = request.data["name"]
        address = request.data["address"]
        profile_photo = None
        user= CustomUser.objects.filter(id=user_id)
        if "profile_photo" in request.data:
          profile_photo =request.data["profile_photo"]
          print(profile_photo,'---pp')
        url = 'media/upload/profile/'
        profile_pic=''
        if CustomUser.objects.filter(phone = contact).exclude(id=user_id).exists():
            validation_status = 'Fail'
            validation_message = 'Contact already exist!'
            return JsonResponse({'status': validation_status, 'message': validation_message})
        if profile_photo is None:
            user_update= user.update(
                phone = contact,
                name=name,
                address=address,
                # email= email,
                )
            validation_status = 'Success'
            validation_message = 'Profile Updated Successfully!'
        else:
            url=''
            profile_pic = upload_photo_edit_image_file(user_id,profile_photo,url,'Profile')
            print(profile_pic,'------')
            user_update= user.update(
                phone = contact,
                name=name,
                address=address,
                profile_pic = profile_pic
                # email= email,
                )
            validation_status = 'Success'
            validation_message = 'Profile Updated Successfully!'   
        return JsonResponse({'status': validation_status, 'message': validation_message})

from django.db.models import Value
from django.db.models.functions import Concat
class ViewProfile(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        # application_detail = list(Custome.objects.filter(by_user_id=self.request.user.id).values())
        # application_detail = list(Applicationform.objects.filter().values())
        # request.data()
        user_id=request.user.id
        
        user_details={}
        photo_url = str(settings.SERVER_BASE_URL)+str(settings.PROFILE_PATH)
        user= CustomUser.objects.filter(id=user_id).values('phone','email','name','address').annotate(pic_url=Concat(Value(photo_url), 'profile_pic'))
        # print(user[0])
        # user_details = 
        validation_status = 'Success'
        # validation_message = 'Profile Successfully!'
        user_data = user[0]   
        return JsonResponse({'status': validation_status,'user':user_data})

class UpdateVehicle(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        app_id = request.data['app_id']
        veh_reg=request.data['veh_reg']
        driver_name= request.data['driver_name']
        phone = request.data['phn']
        mode = request.data['mode']
        lic_img=request.data['lic_img']
        application_detail = Applicationform.objects.filter(id=app_id)

        if not application_detail:
            message = "Application does not exist!"
            return JsonResponse(
                    {'message':message,'status':'Fail'})
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
                url  = 'static/media/upload/license/'
                license_image=upload_photo_edit_image_file(app_id,lic_img,url,'License')
                vehicle = vehicle.update(
                        vehicle_reg_no=veh_reg, license_image=license_image,
                        driver_name=driver_name,driver_phone=phone,
                        mode_of_transport=mode
                        )
                message='Vehicles details updated successfully!'
            # vehicle=vehicle[0]

        # timber_log = Timberlogdetails.objects.filter(appform_id=app_id).values()
        else:
                url  = 'static/media/upload/license/'
                license_image=upload_photo_edit_image_file(app_id,lic_img,url,'License')
        # if is_vehicle == 'yes':
                vehicle = Vehicle_detials.objects.create(app_form_id=app_id,
                    vehicle_reg_no=veh_reg, license_image=license_image,
                    driver_name=driver_name,driver_phone=phone,
                    mode_of_transport=mode
                    )
                message='Vehicles details added successfully!'
        return JsonResponse({'status': 'Success', 'message': message})
        
class UpdateVehicle2(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request,app_id):
        # app_id = request.data['app_id']
        veh_reg=request.data['veh_reg']
        driver_name= request.data['driver_name']
        phone = request.data['phn']
        mode = request.data['mode']
        lic_img=request.data['lic_img']
        #lic_img=''
        #if 'lic_img' not in request.data:
        #    lic_img=None
        #else:
         #   lic_img=request.data['lic_img']

        application_detail = Applicationform.objects.filter(id=app_id)

        if not application_detail:
            message = "Application does not exist!"
            return JsonResponse(
                    {'message':message,'status':'Fail'})
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
                        vehicle_reg_no=veh_reg, license_image=license_image,
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
        return JsonResponse({'status': 'Success', 'message': message,'id':app_id})

def summary_report(request):
    # logo1=settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
    # logo2 = settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
    logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
    logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
    logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
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
        # print(today_stamp,'======',datetime.now())
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
        print('No Data in Summary')
        return HttpResponseRedirect(reverse('officer_dashboard'))

# @login_required
def qr_code_pdf(request,applicant_no):
    # logo1=settings.SERVER_BASE_URL+settings.DEFAULT_LOGO
    logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
    
    logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
    logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
    # image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
    # transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
    # log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
    # signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
    # qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)

    print(applicant_no,"******************")
    application = Applicationform.objects.filter(id=applicant_no).exclude(transit_pass_id=0)
    print(application)
    if application:
        authorizer_name = application[0].approved_by.name if application[0].deemed_approval==False else ''
        application=application.values()
        
        transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
        log_details = Timberlogdetails.objects.filter(appform_id=applicant_no)
        # signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
        qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
        from datetime import datetime
        date_1 = datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
        main_url = settings.SERVER_BASE_URL+"""static/media/qr_code/"""
        # print(application[0]['approved_by_id__name'])
        # print(main_url,log_details[0].log_qr_code)
        req_url=request.META['HTTP_HOST'] 
        print(req_url,"-----HOST")
        # expiry_date = date_1 + datetime.timedelta(days=7)
        from datetime import timedelta
        expiry_date = date_1 + timedelta(days=7)
        context = {'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,"req_url":req_url,'main_url':main_url,
            'transitpass':transitpass,'log_details':log_details}

        response = HttpResponse(content_type='application/pdf')
        today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
        # print(today_stamp,'======',datetime.now())
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
            return JsonResponse({"status":"error","message":"Error"})
        return response
    else:
        print('No Data in Summary')
        return JsonResponse({"status":"error","message":"Error"})



# STATUS_CHOICES = (
#     ('S', _("Submitted")),
#     ('P', _("Pending")),
#     ('A', _("Approved")),
#     ('R', _("Rejected")),
# )
class dashbord_chart(APIView):
    permission_classes = [permissions.IsAuthenticated,]


    def get(self,request):

        tot_app = Applicationform.objects.all().count()
        tot_submitted = Applicationform.objects.filter(application_status="S").count()
        tot_approved = Applicationform.objects.filter(application_status="A").count()
        tot_pending = Applicationform.objects.filter(application_status="P").count()
        tot_rejected = Applicationform.objects.filter(application_status="R").count()

        per_submitted = tot_submitted*100/tot_app

        per_approved = tot_approved*100/tot_app
        per_pending = tot_pending*100/tot_app
        per_rejected = tot_rejected*100/tot_app

        data={}
        print(tot_app,tot_approved,tot_pending,tot_rejected,tot_submitted)
        data["tot_application"] = tot_app


        data["tot_submitted"] = tot_submitted
        data["tot_approved"] = tot_approved
        data["tot_pending"] = tot_pending
        data["tot_rejected"] = tot_rejected


        data["per_submitted"] = per_submitted

        data["per_approved"] = per_approved
        data["per_pending"] = per_pending
        data["per_rejected"] = per_rejected


        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        print(self.request.user.id)        
        return JsonResponse({'status': validation_status, 'message': validation_message,"data":data} , safe=False)




class dashbord_AppList(APIView):
    permission_classes = [permissions.IsAuthenticated,]
    def get(self,request):

        applist= list(Applicationform.objects.all().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message,"data":applist} , safe=False)

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
		print(error,"-")
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
		print(error,"-")
		image_name = ''
	
	return image_name


# @login_required
# @group_required('revenue officer','deputy range officer','forest range officer')
class approve_transit_pass(APIView):
    permission_classes = [permissions.IsAuthenticated,]


    def post(self,request):
        app_id = request.data["app_id"]
        application_detail = Applicationform.objects.filter(id=app_id)
        groups=request.user.groups.values_list('name',flat = True)
        reason = request.data["reason"]
        if application_detail:
            if application_detail[0].application_status=='R':
                return JsonResponse({'message':'Action cannot be taken, Once Application rejected!'})
        else:
            return JsonResponse({'message':'Bad Request!'})
        if request.data["type"] == 'REJECT':
            print(reason,'--reason')

            if groups[0] == "revenue officer":
                application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                disapproved_by=request.user.id,disapproved_by_grp="By Revenue Officer",
                    application_status='R',verify_office = True,verify_office_date = date.today())
            elif groups[0] == "deputy range officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].verify_office==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
                            application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Revenue Officer Action is Pending !'})
                # pass
            elif groups[0] == "forest range officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].depty_range_officer==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Forest Officer",
                        application_status='R',verify_range_officer = True,range_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Deputy Officer Action is Pending !'})
                # pass
            else:
                pass
            return JsonResponse({'message':'Application has been disapproved!'})
            # return render(request,"my_app/tigram/application_details.html",{'applicant':APPLICATION,'applications':application_detail,'message':'Application has been disapproved!'})

        vehicle_detail = Vehicle_detials.objects.filter(app_form_id=app_id)
        # transit_pass = TransitPass.object.filter(app_form_id=app_id)
        if application_detail :

            reason=request.data['reason']
            if groups[0] == "revenue officer":
                application_detail.update(
                reason_office = reason ,
                application_status = 'P',
                approved_by_revenue = request.user,
                verify_office = True,
                verify_office_date = date.today(),
                # transit_pass_id=transit_pass.id,
                # transit_pass_created_date = datetime.date.today(),
                )
            elif groups[0] == "deputy range officer":
                if application_detail[0].verify_office==True:
                    application_detail.update(
                    reason_depty_ranger_office = reason ,
                    application_status = 'P',
                    approved_by_deputy = request.user,
                    depty_range_officer = True,
                    deputy_officer_date = date.today(),
                    # transit_pass_id=transit_pass.id,
                    # transit_pass_created_date = datetime.date.today(),
                    )
                else:
                    JsonResponse({'message':'Application cannot be approved as Revenue Officer Approval is Pending !'})
            # if vehicle_detail:
            elif groups[0] == "forest range officer":
                if application_detail[0].depty_range_officer==True:
                    qr_code=get_qr_code(app_id)
                    print(qr_code,'-----QR')
                    qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
                    print(qr_img,'----qr_path')
                    is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
                    if is_timber:
                        for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
                            log_qr_code=get_log_qr_code(app_id,each_timber['id'])
                            print(log_qr_code,'-----LOG QR')

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
                            print(log_qr_img,'----qr_path')
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
                        reason_range_officer = reason ,
                        application_status = 'A',
                        approved_by = request.user,
                        verify_range_officer = True,
                        range_officer_date = date.today(),
                        transit_pass_id=transit_pass.id,
                        transit_pass_created_date = date.today(),
                        )
                else:
                    JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
                # application_detail[0].save()
                
            else:
                pass
        return JsonResponse({'message':'Application has been approved!'})
"""

class approve_transit_pass(APIView):
    permission_classes = [permissions.IsAuthenticated,]


    def post(self,request):
        app_id = request.data["app_id"]
        application_detail = Applicationform.objects.filter(id=app_id)
        groups=request.user.groups.values_list('name',flat = True)
        reason = request.data["reason"]
        if application_detail:
            if application_detail[0].application_status=='R':
                return JsonResponse({'message':'Action cannot be taken, Once Application rejected!'})
        else:
            return JsonResponse({'message':'Bad Request!'})
        if request.data["type"] == 'REJECT':
            print(reason,'--reason')

            if groups[0] == "revenue officer":
                application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                disapproved_by=request.user.id,disapproved_by_grp="By Revenue Officer",
                    application_status='R',verify_office = True,verify_office_date = date.today())
            elif groups[0] == "deputy range officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].verify_office==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
                            application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Revenue Officer Action is Pending !'})
                # pass
            elif groups[0] == "forest range officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].depty_range_officer==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Forest Officer",
                    application_status='R',verify_range_officer = True,range_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Deputy Officer Action is Pending !'})

                # pass


            elif groups[0] == "division officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].verify_range_officer==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Division Officer",
                    application_status='R',division_officer = True,division_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Forest Range Officer Action is Pending !'})
                # pass
            else:
                pass
            return JsonResponse({'message':'Application has been disapproved!'})
            # return render(request,"my_app/tigram/application_details.html",{'applicant':APPLICATION,'applications':application_detail,'message':'Application has been disapproved!'})

        vehicle_detail = Vehicle_detials.objects.filter(app_form_id=app_id)
        # transit_pass = TransitPass.object.filter(app_form_id=app_id)
        if application_detail :

            reason=request.data['reason']
            if groups[0] == "revenue officer":
                application_detail.update(
                reason_office = reason ,
                application_status = 'P',
                approved_by_revenue = request.user,
                verify_office = True,
                verify_office_date = date.today(),
                # transit_pass_id=transit_pass.id,
                # transit_pass_created_date = datetime.date.today(),
                )
            elif groups[0] == "deputy range officer":
                if application_detail[0].verify_office==True:
                    application_detail.update(
                    reason_depty_ranger_office = reason ,
                    application_status = 'P',
                    approved_by_deputy = request.user,
                    depty_range_officer = True,
                    deputy_officer_date = date.today(),
                    # transit_pass_id=transit_pass.id,
                    # transit_pass_created_date = datetime.date.today(),
                    )
                else:
                    JsonResponse({'message':'Application cannot be approved as Revenue Officer Approval is Pending !'})
            # if vehicle_detail:
            elif groups[0] == "forest range officer":

                if application_detail[0].depty_range_officer==True:
                    if application_detail[0].other_state == False:
                        qr_code=get_qr_code(app_id)
                        print(qr_code,'-----QR')
                        qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
                        print(qr_img,'----qr_path')
                        is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
                        if is_timber:
                            for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
                                log_qr_code=get_log_qr_code(app_id,each_timber['id'])
                                print(log_qr_code,'-----LOG QR')

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
                                print(log_qr_img,'----qr_path')
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
                            reason_range_officer = reason ,
                            application_status = 'A',
                            approved_by = request.user,
                            verify_range_officer = True,
                            range_officer_date = date.today(),
                            transit_pass_id=transit_pass.id,
                            transit_pass_created_date = date.today(),
                            )
                    else:
                        application_detail.update(
                        reason_range_officer = reason ,
                        application_status = 'P',
                        approved_by = request.user,
                        verify_range_officer = True,
                        range_officer_date = date.today(),
                        )
					# JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
			# application_detail[0].save()
                else:
                    JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
            elif groups[0] == "division officer":
                if application_detail[0].verify_range_officer==True:
                    if application_detail[0].other_state == True:
                        qr_code=get_qr_code(app_id)
                        print(qr_code,'-----QR')
                        qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
                        print(qr_img,'----qr_path')
                        is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
                        if is_timber:
                            for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
                                log_qr_code=get_log_qr_code(app_id,each_timber['id'])
                                print(log_qr_code,'-----LOG QR')

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
                                print(log_qr_img,'----qr_path')
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
                            reason_division_officer = reason ,
                            application_status = 'A',
                            approved_by_division = request.user,
                            division_officer = True,
                            division_officer_date = date.today(),
                            transit_pass_id=transit_pass.id,
                            transit_pass_created_date = date.today(),
                            )
                    else:
                        JsonResponse({'message':'Application cannot be approved !'})
                        # JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
                # application_detail[0].save()
                else:
                    JsonResponse({'message':'Application cannot be approved as Forest Range Officer Approval is Pending !'})
            else:
                pass
        return JsonResponse({'message':'Application has been approved!'})
"""









# class changeApp_status(APIView):
#   permission_classes = [permissions.IsAuthenticated,]
#   def post(self,request):

#         # app_id = request.data["app_id"]
#         # app_status = request.data["app_status"]
#         # app_reason = request.data["app_reason"]

#         application_detail = Applicationform.objects.filter(id=app_id)
#         groups=request.user.groups.values_list('name',flat = True)
#         reason = request.POST.get('reason')
#         if application_detail:
#             if application_detail[0].application_status=='R':
#                 return JsonResponse({'message':'Action cannot be taken, Once Application rejected!'})
#         else:
#             return JsonResponse({'message':'Bad Request!'})
#         if request.POST.get('type') == 'REJECT':
#             print(reason,'--reason')

#             if groups[0] == "revenue officer":
#                 application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
#                     application_status='R',verify_office = True,verify_office_date = date.today())
#             elif groups[0] == "deputy range officer":
#                 # application_detail = Applicationform.objects.filter(id=app_id)
#                 if application_detail[0].verify_office==True:
#                     application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
#                             application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
#                 else:
#                     JsonResponse({'message':'Application cannot be disapproved as Revenue Officer Action is Pending !'})
#                 # pass
#             elif groups[0] == "forest range officer":
#                 # application_detail = Applicationform.objects.filter(id=app_id)
#                 if application_detail[0].depty_range_officer==True:
#                     application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
#                         application_status='R',verify_range_officer = True,range_officer_date = date.today())
#                 else:
#                     JsonResponse({'message':'Application cannot be disapproved as Deputy Officer Action is Pending !'})
#                 # pass
#             else:
#                 pass
#             return JsonResponse({'message':'Application has been disapproved!'})
#             # return render(request,"my_app/tigram/application_details.html",{'applicant':APPLICATION,'applications':application_detail,'message':'Application has been disapproved!'})

#         vehicle_detail = Vehicle_detials.objects.filter(app_form_id=app_id)
#         # transit_pass = TransitPass.object.filter(app_form_id=app_id)
#         if application_detail :

#             reason=request.POST.get('reason')
#             if groups[0] == "revenue officer":
#                 application_detail.update(
#                 reason_office = reason ,
#                 application_status = 'P',
#                 approved_by = request.user,
#                 verify_office = True,
#                 verify_office_date = date.today(),
#                 # transit_pass_id=transit_pass.id,
#                 # transit_pass_created_date = datetime.date.today(),
#                 )
#             elif groups[0] == "deputy range officer":
#                 if application_detail[0].verify_office==True:
#                     application_detail.update(
#                     reason_depty_ranger_office = reason ,
#                     application_status = 'P',
#                     approved_by = request.user,
#                     depty_range_officer = True,
#                     deputy_officer_date = date.today(),
#                     # transit_pass_id=transit_pass.id,
#                     # transit_pass_created_date = datetime.date.today(),
#                     )
#                 else:
#                     JsonResponse({'message':'Application cannot be approved as Revenue Officer Approval is Pending !'})
#             # if vehicle_detail:
#             elif groups[0] == "forest range officer":
#                 if application_detail[0].depty_range_officer==True:
#                     qr_code=get_qr_code(app_id)
#                     print(qr_code,'-----QR')
#                     qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
#                     print(qr_img,'----qr_path')
#                     is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
#                     if is_timber:
#                         for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
#                             log_qr_code=get_log_qr_code(app_id,each_timber['id'])
#                             print(log_qr_code,'-----LOG QR')

#                             log_data='Log Details:\n'
#                             log_data+='Application No. :-'+application_detail[0].application_no+'\n'
#                             log_data+='Destination :-'+application_detail[0].destination_details+'\n'
#                             log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
#                             log_data+='Length :-'+str(each_timber['length'])+'\n'
#                             log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
#                             log_data+='Volume :-'+str(each_timber['volume'])+'\n'
#                             log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
#                             log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
#                             log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
#                             print(log_qr_img,'----qr_path')
#                             is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img)

#                     if vehicle_detail:
#                         # vehicle=vehicle_detail[0]
#                         transit_pass=TransitPass.objects.create(
#                             vehicle_reg_no=vehicle_detail[0].vehicle_reg_no,
#                             driver_name = vehicle_detail[0].driver_name,
#                             driver_phone = vehicle_detail[0].driver_phone,
#                             mode_of_transport = vehicle_detail[0].mode_of_transport,
#                             license_image = vehicle_detail[0].license_image,
#                             photo_of_vehicle_with_number = vehicle_detail[0].photo_of_vehicle_with_number,
#                             state = application_detail[0].state,
#                             district = application_detail[0].district,
#                             taluka = application_detail[0].taluka,
#                             block = application_detail[0].block,
#                             village = application_detail[0].village,
#                             qr_code = qr_code,
#                             qr_code_img =qr_img, 
#                             app_form_id = app_id
#                         )
#                     else:
#                         transit_pass=TransitPass.objects.create(
#                             state = application_detail[0].state,
#                             district = application_detail[0].district,
#                             taluka = application_detail[0].taluka,
#                             block = application_detail[0].block,
#                             village = application_detail[0].village,
#                             qr_code = qr_code,
#                             qr_code_img =qr_img, 
#                             app_form_id = app_id
#                         )
#                     application_detail.update(
#                         reason_range_officer = reason ,
#                         application_status = 'A',
#                         approved_by = request.user,
#                         verify_range_officer = True,
#                         range_officer_date = date.today(),
#                         transit_pass_id=transit_pass.id,
#                         transit_pass_created_date = date.today(),
#                         )
#                 else:
#                     JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
#                 # application_detail[0].save()
                
#             else:
#                 pass
#         return JsonResponse({'message':'Application has been approved!'})




class ApprovedListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        groups=request.user.groups.values_list('name',flat = True)
        officer_range=''
        validation_status = 'Error'
        validation_message = 'No data Found.'
        if groups[0] =='revenue officer':
            officer_range=RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
            if officer_range !='':
                application_detail = list(Applicationform.objects.filter(verify_office=True,area_range=officer_range[0].range_name.name,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
                validation_status = 'Success'
                validation_message = 'Data Feteched Successfully.'
            else:
                application_detail = list(Applicationform.objects.filter(verify_office=True,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')|Q(application_status='P')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
                validation_status = 'Success'
                validation_message = 'Data Feteched Successfully.'

            
        elif groups[0] =='deputy range officer':
         application_detail = list(Applicationform.objects.filter(d = request.user.id,deemed_approval=False,is_noc=False).values().order_by('-id'))
         validation_status = 'Success'
         validation_message = 'Data Feteched Successfully.'
        elif groups[0] =='forest range officer':
         application_detail = list(Applicationform.objects.filter(r = request.user.id,deemed_approval=False,is_noc=False ).filter(Q(application_status="A")|Q(application_status="R")).values().order_by('-id'))
         validation_status = 'Success'
         validation_message = 'Data Feteched Successfully.'


          
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)




class DfoApprovedListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):

        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            application_detail = list(Applicationform.objects.filter(verify_office=True,area_range__iexact =area_range,division__iexact = div[0]["division_name__name"],deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            application_detail = list(Applicationform.objects.filter(verify_office=True,division__iexact = div[0]["division_name__name"],deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))


       # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)


class sfdApprovedListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):

        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            application_detail = list(Applicationform.objects.filter(verify_office=True,area_range__iexact =area_range,division__iexact = division,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            application_detail = list(Applicationform.objects.filter(verify_office=True,area_range__iexact =area_range,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            application_detail = list(Applicationform.objects.filter(verify_office=True,division__iexact = division,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))



        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            application_detail = list(Applicationform.objects.filter(verify_office=True,deemed_approval=False,is_noc=False).filter(Q(application_status='A')|Q(application_status='R')).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))


       # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)





class PendingListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        groups=request.user.groups.values_list('name',flat = True)
        officer_range=''
        if groups[0] =='revenue officer':
            officer_range=RevenueOfficerdetail.objects.filter(Rev_user_id=request.user.id)
            if officer_range !='':
                application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')|Q(application_status='I')|Q(application_status='L')).filter(verify_office=False,area_range=officer_range[0].range_name.name,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
            else:
                application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')|Q(application_status='I')|Q(application_status='L')).filter(verify_office=False,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))


            
        elif groups[0] =='deputy range officer':
            officer_range=ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
            if officer_range !='':
                application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')|Q(application_status='I')|Q(application_status='L')).filter(depty_range_officer=False,area_range=officer_range[0].range_name.name,is_noc=False,d=request.user.id).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
            else:
                application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')|Q(application_status='I')|Q(application_status='L')).filter(depty_range_officer=False,is_noc=False,d=request.user.id).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))

        elif groups[0] =='forest range officer':
            officer_range=ForestOfficerdetail.objects.filter(fod_user_id=request.user.id)
            if officer_range !='':
                # application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(Q(verify_office=False)|Q(application_status='R'),verify_office=False,area_range=officer_range[0].range_name.name,is_noc=False).values().order_by('-id'))
                application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')|Q(application_status='I')|Q(application_status='L')).filter(verify_range_officer=False,area_range=officer_range[0].range_name.name,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))

            else:
                application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')|Q(application_status='I')|Q(application_status='L')).filter(verify_range_officer=False,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))

        
        # application_detail = list(Applicationform.objects.filter().values())
        #import date
        #print(application_detail[0]["tp_expiry_date"],"*****************")

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)



class sfdPendingListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(verify_office=False,area_range=area_range,division=division,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(verify_office=False,area_range=area_range,division=division,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(verify_office=False,area_range=area_range,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(verify_office=False,division=division,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(verify_office=False,is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))


        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)





class DfoPendingListViewApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(area_range__iexact =area_range,division__iexact = div[0]["division_name__name"],is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            application_detail = list(Applicationform.objects.exclude(Q(application_status='A')|Q(application_status='R')).filter(division__iexact = div[0]["division_name__name"],is_noc=False).values().annotate(assigned_deputy1_name=F('assigned_deputy1_id__name'),assigned_deputy2_name=F('assigned_deputy2_id__name')).order_by('-id'))


        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)

class table_one(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        ty = list(Applicationform.objects.filter(is_noc=False).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))
        return Response(ty, status=status.HTTP_200_OK)

class dfo_table_one(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        print(request.user)
        area_range = request.data["area_range"]
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            ty = list(Applicationform.objects.filter(is_noc=False,area_range__iexact =area_range,division__iexact = div[0]["division_name__name"]).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))


        else:

            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            ty = list(Applicationform.objects.filter(is_noc=False,division__iexact = div[0]["division_name__name"]).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))

        return Response(ty, status=status.HTTP_200_OK)


class sfd_table_one(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        print(request.user)
        division = request.data["division"]
        area_range = request.data["area_range"]
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            ty = list(Applicationform.objects.filter(is_noc=False,area_range__iexact =area_range,division_iexact=division).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))

        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            ty = list(Applicationform.objects.filter(is_noc=False,area_range__iexact =area_range,division_iexact=division).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))

        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            ty = list(Applicationform.objects.filter(is_noc=False,division_iexact=division).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))

        else:

            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            ty = list(Applicationform.objects.filter(is_noc=False).values('created_date').annotate(no_of_received=Count('pk')).annotate(no_of_approved=Count(Case(When(application_status='A',then=F('id')),output_field=IntegerField(),))).annotate(no_of_rejected=Count(Case(When(application_status='R',then=F('id')),output_field=IntegerField(),))).order_by('created_date'))


        return Response(ty, status=status.HTTP_200_OK)




class table_two(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        
        app_list = Applicationform.objects.filter(application_status='R',is_noc=False).values('disapproved_reason')
   
        len_aplist = len(app_list)
        dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disapproved_reason')) }

        return Response(dict_of_percentages, status=status.HTTP_200_OK)


class dfo_table_two(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Applicationform.objects.filter(application_status='R',is_noc=False,area_range__iexact=area_range,division__iexact = div[0]["division_name__name"]).values('disapproved_reason')
    
            len_aplist = len(app_list)
            dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disapproved_reason')) }

        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Applicationform.objects.filter(application_status='R',is_noc=False,division__iexact = div[0]["division_name__name"]).values('disapproved_reason')
    
            len_aplist = len(app_list)
            dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disappr oved_reason')) }

        return Response(dict_of_percentages, status=status.HTTP_200_OK)


class sfd_table_two(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        division = request.data["division"]
        area_range = request.data["area_range"]
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='R',is_noc=False,area_range__iexact =area_range,division_iexact=division).values('disapproved_reason')
    
            len_aplist = len(app_list)
            dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disapproved_reason')) }
            
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='R',is_noc=False,area_range__iexact =area_range).values('disapproved_reason')
    
            len_aplist = len(app_list)
            dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disapproved_reason')) }
            
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='R',is_noc=False,division_iexact=division).values('disapproved_reason')
    
            len_aplist = len(app_list)
            dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disapproved_reason')) }

        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='R',is_noc=False).values('disapproved_reason')
    
            len_aplist = len(app_list)
            dict_of_percentages = { reject_type['disapproved_reason']:reject_type['disapproved_reason__count'] * 100/len_aplist for reject_type in app_list.annotate(Count('disapproved_reason')) }

        return Response(dict_of_percentages, status=status.HTTP_200_OK)



class table_three(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        applications_list=Timberlogdetails.objects.filter(appform__is_noc=False)
        app_list_ty=applications_list.values('species_of_tree',
        'appform__created_date').annotate(
         no_of_trees=Count('species_of_tree')   
        ).annotate(
         total_no_of_trees=Count('id')  
        ).annotate(
        volume_sum=Sum('volume')
        )
        len_aplist = len(applications_list)
        applications_list_ty = Applicationform.objects.filter(is_noc=False).values('created_date').order_by('created_date').annotate(
            as_float=Cast('total_trees', FloatField())
            ).annotate(
            total_trees=Sum('as_float'),
            )

        context = {}
        context["tabel"]=app_list_ty
        context["graph"] = applications_list_ty
        return Response(context, status=status.HTTP_200_OK)


class dfo_table_three(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            applications_list=Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            app_list_ty=applications_list.values('species_of_tree',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            total_no_of_trees=Count('id')  
            ).annotate(
            volume_sum=Sum('volume')
            )
            len_aplist = len(applications_list)
            applications_list_ty = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range,division__iexact = div[0]["division_name__name"]).values('created_date').order_by('created_date').annotate(
                as_float=Cast('total_trees', FloatField())
                ).annotate(
                total_trees=Sum('as_float'),
                )


        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)

            applications_list=Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = div[0]["division_name__name"])
            app_list_ty=applications_list.values('species_of_tree',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            total_no_of_trees=Count('id')  
            ).annotate(
            volume_sum=Sum('volume')
            )
            len_aplist = len(applications_list)
            applications_list_ty = Applicationform.objects.filter(is_noc=False,division__iexact = div[0]["division_name__name"]).values('created_date').order_by('created_date').annotate(
                as_float=Cast('total_trees', FloatField())
                ).annotate(
                total_trees=Sum('as_float'),
                )

        context = {}
        context["tabel"]=app_list_ty
        context["graph"] = applications_list_ty
        return Response(context, status=status.HTTP_200_OK)


class sfd_table_three(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        division = request.data["division"]
        area_range = request.data["area_range"]
        if area_range !=""and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            applications_list=Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = division)
            app_list_ty=applications_list.values('species_of_tree',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            total_no_of_trees=Count('id')  
            ).annotate(
            volume_sum=Sum('volume')
            )
            len_aplist = len(applications_list)
            applications_list_ty = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range,division__iexact = division).values('created_date').order_by('created_date').annotate(
                as_float=Cast('total_trees', FloatField())
                ).annotate(
                total_trees=Sum('as_float'),
                )
        elif area_range !="" and division=="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            applications_list=Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range)
            app_list_ty=applications_list.values('species_of_tree',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            total_no_of_trees=Count('id')  
            ).annotate(
            volume_sum=Sum('volume')
            )
            len_aplist = len(applications_list)
            applications_list_ty = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range,appform__state__iexact = div[0]["state_name"]).values('created_date').order_by('created_date').annotate(
                as_float=Cast('total_trees', FloatField())
                ).annotate(
                total_trees=Sum('as_float'),
                )

        elif area_range =="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            applications_list=Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = division)
            app_list_ty=applications_list.values('species_of_tree',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            total_no_of_trees=Count('id')  
            ).annotate(
            volume_sum=Sum('volume')
            )
            len_aplist = len(applications_list)
            applications_list_ty = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range,division__iexact = div[0]["division_name__name"]).values('created_date').order_by('created_date').annotate(
                as_float=Cast('total_trees', FloatField())
                ).annotate(
                total_trees=Sum('as_float'),
                )

        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            applications_list=Timberlogdetails.objects.filter(appform__is_noc=False)
            app_list_ty=applications_list.values('species_of_tree',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            total_no_of_trees=Count('id')  
            ).annotate(
            volume_sum=Sum('volume')
            )
            len_aplist = len(applications_list)
            applications_list_ty = Applicationform.objects.filter(is_noc=False).values('created_date').order_by('created_date').annotate(
                as_float=Cast('total_trees', FloatField())
                ).annotate(
                total_trees=Sum('as_float'),
                )

        context = {}
        context["tabel"]=app_list_ty
        context["graph"] = applications_list_ty
        return Response(context, status=status.HTTP_200_OK)















class table_four(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
        totalvolume=app_list.aggregate(Sum('volume'))
        print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)




class dfo_table_four(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = div[0]["division_name__name"])
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class sfd_table_four(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        division = request.data["division"]
        area_range = request.data["area_range"]
        context={}
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = division)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = division)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)





class table_five(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
        app_list=app_list.values('species_of_tree','appform__destination_details',
        'appform__created_date').annotate(
         no_of_trees=Count('species_of_tree')   
        ).annotate(
        volume_sum=Sum('volume')
        ).order_by('appform__created_date')
        len_aplist = len(app_list)
        
        context['applicantions']=list(app_list)
        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class dfo_table_five(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = div[0]["division_name__name"])
            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        context['applicantions']=list(app_list)
        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class sfd_table_five(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        division = request.data["division"]
        area_range = request.data["area_range"]
        context={}
        if area_range !="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = division)
            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        elif area_range =="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = division)
            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
            
        elif area_range !="" and division=="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range)
            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
            no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        context['applicantions']=list(app_list)
        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class table_six(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
        totalvolume=app_list.aggregate(Sum('volume'))
        print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)




class dfo_table_six(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = div[0]["division_name__name"])
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)




class dfo_table_six(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = div[0]["division_name__name"])
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class sfd_table_six(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division !="" :
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact=division)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
            
            
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        
        
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact=division)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
            app_list=app_list.values('appform__destination_details',
            'appform__created_date').annotate(
            volume_sum=Sum('volume')
            ).annotate(
            volume_percentage=(F('volume_sum')/totalvolume['volume__sum'])*100,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
            totalvolume=app_list.aggregate(Sum('volume'))
            print(totalvolume,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)




class table_seven(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Applicationform.objects.filter(application_status='A',is_noc=False)
        totalapp=app_list.count()
        print(totalapp,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class dfo_table_seven(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Applicationform.objects.filter(application_status='A',is_noc=False,area_range__iexact=area_range,division__iexact = div[0]["division_name__name"])
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Applicationform.objects.filter(application_status='A',is_noc=False,division__iexact = div[0]["division_name__name"])
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class sfd_table_seven(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='A',is_noc=False,area_range__iexact=area_range,division__iexact = division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
            
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='A',is_noc=False,area_range__iexact=area_range)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
            
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='A',is_noc=False,division__iexact = division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(application_status='A',is_noc=False,area_range__iexact=area_range,division__iexact = division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class table_eight(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Applicationform.objects.filter(is_noc=False)
        totalapp=app_list.count()
        print(totalapp,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class dfo_table_eight(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range,division__iexact = div[0]["division_name__name"])
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
            app_list=app_list.values(
            'created_date','purpose').annotate(
            no_of_applicantions=Count('id')
            ).annotate(
            applications_percentage=F('no_of_applicantions')*100/totalapp,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('created_date')
            len_aplist = len(app_list)
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)
            app_list = Applicationform.objects.filter(is_noc=False,division__iexact = div[0]["division_name__name"])
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class sfd_table_eight(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self,request):
        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range,division__iexact = division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
            app_list=app_list.values(
            'created_date','purpose').annotate(
            no_of_applicantions=Count('id')
            ).annotate(
            applications_percentage=F('no_of_applicantions')*100/totalapp,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('created_date')
            len_aplist = len(app_list)
            
        elif area_range !="" and division=="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(is_noc=False,area_range__iexact=area_range)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
            app_list=app_list.values(
            'created_date','purpose').annotate(
            no_of_applicantions=Count('id')
            ).annotate(
            applications_percentage=F('no_of_applicantions')*100/totalapp,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('created_date')
            len_aplist = len(app_list)
            
        elif area_range =="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(is_noc=False,division__iexact=division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
            app_list=app_list.values(
            'created_date','purpose').annotate(
            no_of_applicantions=Count('id')
            ).annotate(
            applications_percentage=F('no_of_applicantions')*100/totalapp,
            # output_field=format('volume_percentage', ".2f"),
            ).order_by('created_date')
            len_aplist = len(app_list)
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)
            app_list = Applicationform.objects.filter(is_noc=False)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class table_nine(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
        totalapp=app_list.count()
        print(totalapp,'-----xxxxxxxxx---------')
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

        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class dfo_table_nine(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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

        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class sfd_table_nine(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self,request):
        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range,appform__division__iexact = division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        elif area_range !="" and division =="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__area_range__iexact=area_range)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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
        elif area_range =="" and division !="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=False,appform__division__iexact = division)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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




        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=False)
            totalapp=app_list.count()
            print(totalapp,'-----xxxxxxxxx---------')
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

        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)





#noc Reports

class table_noc_one(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        # ty=list(request.user.groups.all().values('name'))
        # gname=ty[0]["name"]
        # print(gname)
        # gname = Group
        context={}
        app_list = Timberlogdetails.objects.filter(appform__is_noc=True)
        app_list=app_list.values('species_of_tree','appform__destination_details',
        'appform__created_date').annotate(
         no_of_trees=Count('species_of_tree')   
        ).annotate(
        volume_sum=Sum('volume')
        ).order_by('appform__created_date')
        len_aplist = len(app_list)
        
        context['applicantions']=list(app_list)
        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)


class dfo_table_noc_one(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self,request):
        area_range = request.data["area_range"]
        context={}
        if area_range !="":
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=True,appform__area_range__iexact=area_range,appform__division__iexact = div[0]["division_name__name"])

            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
                no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = DivisionOfficerdetail.objects.filter(div_user_id = request.user.id).values('id','division_name__name','division_name__id')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=True,appform__division__iexact = div[0]["division_name__name"])

            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
                no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        
        context['applicantions']=list(app_list)
        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class sfd_table_noc_one(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self,request):
        area_range = request.data["area_range"]
        division = request.data["division"]
        context={}
        if area_range !="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=True,appform__area_range__iexact=area_range,appform__division__iexact = division)

            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
                no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
            
        elif area_range !="" and division=="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=True,appform__area_range__iexact=area_range)

            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
                no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
            
        elif area_range =="" and division!="":
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=True,appform__division__iexact = division)

            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
                no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        else:
            div = StateOfficerdetail.objects.filter(state_user_id = request.user.id).values('id','state_name')
            print(div)

            app_list = Timberlogdetails.objects.filter(appform__is_noc=True)

            app_list=app_list.values('species_of_tree','appform__destination_details',
            'appform__created_date').annotate(
                no_of_trees=Count('species_of_tree')   
            ).annotate(
            volume_sum=Sum('volume')
            ).order_by('appform__created_date')
            len_aplist = len(app_list)
        
        context['applicantions']=list(app_list)
        # context['group'] = list(groups)
        print(context,'--=context')
        return JsonResponse(context,safe=False)



class Apply_for_noc(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):

        name = ""
        address = ""
        survey_number = ""
        num_trees_proposed_cut = ""
        village = ""
        taluka = ""
        block = ""
        district = ""
        proof_of_ownership_img = ""
        species_of_tree  = ""
        purpose = ""
        log_details = []
        revenue_application = ""
        revenue_approval = ""
        declaration = ""
        location_sktech = ""
        tree_ownership_detail = ""
        photo_id_proof = "" 
        photo_id_proof_img = "" 
        destination_details = "" 
        vehicle_reg_no = "" 
        driver_name = "" 
        driver_phone = "" 
        mode_of_transport = "" 
        license_image = "" 
        signature_img = "" 

        validation_status = 'error'
        validation_message = 'Error'
        name=request.data["name"]
        address=request.data["address"]
        survey_no=request.data["survey_no"]
        tree_proposed=request.data["tree_proposed"]
        village=request.data["village"]
        district=request.data["district"]
        block=request.data["block"]
        taluka=request.data["taluka"]
        division=request.data["division"]
        area_range=request.data["area_range"]
        pincode=request.data["pincode"]
        # print(request.FILES)
        # ownership_proof_img=request.data["ownership_proof_img"]
        # revenue_application_img=request.data["revenue_application_img"]
        # revenue_approval_img=request.data["revenue_approval_img"]
        # declaration_img=request.data["declaration_img"]
        # location_sketch_img=request.data["location_sketch_img"]
        # tree_ownership_img=request.data["tree_ownership_img"]
        aadhar_card_img=request.data["aadhar_card_img"]
        signature_img = request.data["signature_img"]
        # lic_img=request.data["licence_img"]
        tree_species=request.data["tree_species"]
        purpose = request.data["purpose_cut"]
        veh_reg=request.data["vehicel_reg"]
        driver_name= request.data["driver_name"]
        phone = request.data["phone"]
        mode = request.data["mode"]
        log_details = request.data["log_details"]
        trees_cutted = request.data["trees_cutted"]
        destination_address = request.data["destination_address"]
        print("___________________________")
        url='static/media/'
        application = Applicationform.objects.create(is_noc=True,
            name=name,address=address,destination_details=destination_address,
            survey_no=survey_no,village=village,total_trees=tree_proposed,
            district=district,species_of_trees=tree_species,pincode=pincode,
            purpose=purpose,block=block,taluka=taluka,division=division,
            area_range=area_range,by_user=request.user
            )
        print(application)
        saved_image=upload_product_image_file(application.id,aadhar_card_img,url,'AadharCard')
        # saved_image_2=upload_product_image_file(application.id,revenue_approval_img,url,'RevenueApproval')
        # saved_image_1=upload_product_image_file(application.id,declaration_img,url,'Declaration')
        # saved_image_3=upload_product_image_file(application.id,revenue_application_img,url,'RevenueApplication')
        # saved_image_4=upload_product_image_file(application.id,location_sketch_img,url,'LocationSketch')
        # saved_image_5=upload_product_image_file(application.id,tree_ownership_img,url,'TreeOwnership')
        # saved_image_6=upload_product_image_file(application.id,ownership_proof_img,url,'ProofOfOwnership')
        # # saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')
        saved_image_8=upload_product_image_file(application.id,signature_img,url,'Signature')
        # application.proof_of_ownership_of_tree=saved_image_6

                
        image_doc=image_documents.objects.create(app_form=application,aadhar_detail=saved_image,
                signature_img=saved_image_8
            )
        # application.revenue_approval = True
        # application.declaration = True
        uid=request.user.id
        
        application.application_no=generate_noc_app_id(uid,application.id)
 #       application_no=generate_app_id(uid,application.id)
        #clprint(application_no,"*******************")
        application.signature_img = True
        # application.revenue_application = True
        # application.location_sktech = True
        # application.tree_ownership_detail = True
        application.aadhar_detail = True
        tem = Applicationform.objects.filter(id = application.id).update(application_no=application.id)
        qr_code=get_qr_code(application.id)
        print(qr_code,'-----QR')
        qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, application.id)
        print(qr_img,'----qr_path')
# veh_reg=request.data["vehicel_reg"]
#         driver_name= request.data["driver_name"]
#         phone = request.data["phone"]
#         mode = request.data["mode"]


        transit_pass=TransitPass.objects.create(state = application.state,district = application.district,taluka = application.taluka,block = application.block,village = application.village,qr_code = qr_code,qr_code_img =qr_img,app_form_id = application.id
                            ,vehicle_reg_no=veh_reg,
                            driver_name = driver_name,
                            driver_phone = phone,
                            mode_of_transport = mode)
                            # license_image = vehicle_detail[0].license_image,
                            # photo_of_vehicle_with_number = vehicle_detail[0].photo_of_vehicle_with_number,
        print(transit_pass.id,"&&&&&&&&&&&&&&&&************8")
        # up_det = Applicationform.objects.filter(id = application.id).update(transit_pass_id = transit_pass.id)
        # application.trees_cutted = True
        #print(")s",tem)
        tlog =[]
        application.trees_cutted= True
        application.transit_pass_id = transit_pass.id

        if log_details!="" : 
            for i in log_details:
                print(i)

                timber = Timberlogdetails(appform=application,species_of_tree=i["species_of_tree"], 
                length=i["length"], breadth=i["breadth"],volume=i["volume"],latitude=i["latitude"],longitude=i["longitude"])
                tlog.append(timber)
            Timberlogdetails.objects.bulk_create(tlog)
        application.save()
        # if lic_img!="":
        #     saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')

        vehicle = Vehicle_detials.objects.create(app_form=application,
            vehicle_reg_no=veh_reg,
            driver_name=driver_name,driver_phone=phone,
            mode_of_transport=mode
            )

            #     vehicle = Vehicle_detials.objects.create(app_form=application,
            # license_image=saved_image_7,vehicle_reg_no=veh_reg,
            # driver_name=driver_name,driver_phone=phone,
            # mode_of_transport=mode
            # )
        validation_status = 'Success'
        validation_message = 'Data Saved Successfully.'   
        print(self.request.user.id)        
        return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)



class NocListApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        application_detail = list(Applicationform.objects.filter(is_noc=True).values().order_by('-id'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)


class UserNocListApplication(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        application_detail = list(Applicationform.objects.filter(is_noc=True,by_user_id=self.request.user.id).values().order_by('-id'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)


def new_noc_pdf(request,applicant_no):
    logo1=settings.SERVER_BASE_URL+settings.USAID_LOGO
    logo2 = settings.SERVER_BASE_URL+settings.KERALAFOREST_LOGO
    logo3 = settings.SERVER_BASE_URL+"static/images/tigram_logo03.png"
    application = Applicationform.objects.filter(id=applicant_no)
    if application:
        import datetime
        application=application.values()
        image_document = image_documents.objects.filter(app_form_id=applicant_no)[0]
        transitpass = TransitPass.objects.filter(app_form_id=applicant_no)[0]
        log_details = Timberlogdetails.objects.filter(appform_id=applicant_no).values()
        signature_img = settings.SERVER_BASE_URL+"""static/media/upload/signature/"""+ str(image_document.signature_img)
        qr_img = settings.SERVER_BASE_URL+"""static/media/qr_code/"""+ str(transitpass.qr_code_img)
        date_1 = datetime.datetime.strptime(str(application[0]['transit_pass_created_date']), "%Y-%m-%d")
        main_url=settings.SERVER_BASE_URL+'static/media/qr_code/'
        log={}
        expiry_date = date_1 + datetime.timedelta(days=7)
        context = {'application':application,"logo1":logo1,"logo2":logo2,"logo3":logo3,'main_url':main_url,
            'qr_img':qr_img,'log_details':log_details,'signature_img':signature_img,
            'transitpass':transitpass,'expiry_date':expiry_date}
        from datetime import datetime

        response = HttpResponse(content_type='application/pdf')
        today_stamp= str(datetime.now()).replace(' ','').replace(':','').replace('.','').replace('-','')
        filename= 'NOC-'+str(application[0]['application_no'])+'-'+today_stamp+''
        response['Content-Disposition'] = 'attachment; filename="'+filename+'.pdf"'
        template = get_template('pdf_template/noc.html')
        html = template.render(context)
        pisa_status = pisa.CreatePDF(
            html, dest=response, link_callback=link_callback)
        return response
    else:
        print('No Data in Summary')
        return JsonResponse({'status': "error", 'message': "Error"} , safe=False)


class NocViewApplication(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):

        app_id = request.data["app_id"]
        groups=list(request.user.groups.values_list('name',flat = True))
        
        chck_app = Applicationform.objects.filter(id=app_id,is_noc=True)
        if chck_app:
            pass
        else:
            validation_status = 'Error'
            validation_message = 'Application Not Found.'   
            return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)

            
            
        application_detail = list(Applicationform.objects.filter(id=app_id).values())
         
        # if application_detail[0]["proof_of_ownership_of_tree"]!="":
        #     application_detail[0].update({"proof_of_ownership_of_tree":settings.SERVER_BASE_URL+settings.PROOF_OF_OWNERSHIP_PATH+application_detail[0]["proof_of_ownership_of_tree"]})
            # print("*12222222222222222222222222222")

        # trees_species_list = list(TreeSpecies.objects.all().values('name'))
        # image_document =""
        # print("********************")
                #         "revenue_approval": "RevenueApproval_94_image.png",
                # "declaration": "Declaration_94_image.png",
                # "revenue_application": "RevenueApplication_94_image.png",
                # "location_sktech": "LocationSketch_94_image.png",
                # "tree_ownership_detail": "TreeOwnership_94_image.png",
                # "aadhar_detail": "AadharCard_94_image.png"

        image_document = list(image_documents.objects.filter(app_form_id=app_id).values())
        t1 = image_document[0]["signature_img"]
        image_document[0].update({"signature_img":settings.SERVER_BASE_URL+settings.SIGN_PATH +image_document[0]["signature_img"]})
        # image_document[0].update({"declaration":settings.SERVER_BASE_URL+settings.DECLARATION_PATH +image_document[0]["declaration"]})
        # image_document[0].update({"revenue_approval":settings.SERVER_BASE_URL+settings.REVENUE_APPROVAL_PATH +image_document[0]["revenue_approval"]})
        # image_document[0].update({"location_sktech":settings.SERVER_BASE_URL+settings.LOCATION_SKETCH_PATH +image_document[0]["location_sktech"]})
        # image_document[0].update({"tree_ownership_detail":settings.SERVER_BASE_URL+settings.TREE_OWNERSHIP_PATH +image_document[0]["tree_ownership_detail"]})
        image_document[0].update({"aadhar_detail":settings.SERVER_BASE_URL+settings.AADHAR_IMAGE_PATH +image_document[0]["aadhar_detail"]})
        # image_document[0].update({"revenue_application":settings.SERVER_BASE_URL+settings.REVENUE_APPLICATION_PATH +image_document[0]["revenue_application"]})



        # if application_detail:
        vehicle = list(Vehicle_detials.objects.filter(app_form_id=app_id).values())
        #print(vehicle[0],"22222222222222222222222")
        isvehicle=''
        if vehicle:
            print("$$$$$$$$$$$")
        #     vehicle=vehicle[0]
        #     vehicle.update({"license_image":settings.SERVER_BASE_URL+settings.LICENSE_PATH+vehicle["license_image"]})
            # vehicle.update({"photo_of_vehicle_with_number":settings.SERVER_BASE_URL+settings.PHOTO_OF_VEHICLE+vehicle["photo_of_vehicle_with_number"]})

            

        else:
            isvehicle = 'Not Applicable'
        is_timberlog=''
        timber_log = Timberlogdetails.objects.filter(appform_id=app_id)
        if timber_log:
            timber_log=list(timber_log.values())
            # for tl in timber_log:
            #     tl.update({"log_qr_code_img":settings.SERVER_BASE_URL+settings.LOG_QR})
        else:
            timber_log = ""
            is_timberlog='N/A'
        print("********************")

        # transit_pass_exist = TransitPass.objects.filter(app_form_id=app_id).exists()
        transit_pass_exist = False
        # if groups[0] == "revenue officer" and application_detail[0].verify_office == True:
        #     transit_pass_exist = True
        # elif groups[0] == "deputy range officer" and application_detail[0].depty_range_officer == True:
        #     transit_pass_exist = True
        # elif groups[0] == "forest range officer" and application_detail[0].verify_range_officer == True:
        #     transit_pass_exist = True
        # else:
        #     pass
        print(transit_pass_exist,'----TP')
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        print(self.request.user.id)
        data = {
            'applications':application_detail,'image_documents':image_document,
            'vehicle':vehicle,'timber_log':timber_log,
            'isvehicle':isvehicle,'is_timberlog':is_timberlog}
        print(data,"&&&&&&&&&&&&&&&&&&&&&&&&/")
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':data} , safe=False)



class DeemedApprovedList(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def get(self, request):

        application_detail = list(Applicationform.objects.filter(deemed_approval=True).values().order_by('-id'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)
        
        

class GetLocationDataNew(APIView):
    # user = self.request.user.id
    permission_classes = [permissions.AllowAny,]

    def get(self,request):
        temp = []

        dist = District.objects.all()
        taluka = Taluka.objects.all()
        village = Village.objects.all()

        for i in dist:
            dst = {}
            mc = []
            clst1 = []
            tclst1 = []
            mc2 = {}
            dst["district_name"] = i.district_name
            m1 = taluka.filter(dist_id = i.id)
            # c1 = council.filter(dist_id=i.id)
            # t1 = tal.filter(dist_id=i.id)
            # if m1:
            for j in m1:
                mc1 = {}
                mc1["taluka_name"]  = j.taluka_name
                m2 = village.filter(taluka_id = j.id)
                if m2:
                    wlst = []
                    for i in m2:
                        wlst.append(i.village_name)
                    mc1["village_name"]  = wlst
                mc.append(mc1)
                dst["taluka"] = mc
            temp.append(dst)
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':temp} , safe=False)




#Form Two

class Formtwophaseone(APIView):
    # Allow any user (authenticated or not) to access this url 
    # authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        location_img1 = ""
        location_img2 = ""
        location_img3 = ""
        location_img4 = ""
        image1_lat = ""
        image2_lat = ""
        image3_lat = ""
        image4_lat = ""
        image1_log = ""
        image2_log = ""
        image3_log = ""
        image4_log = ""
        spec_details = ""
        validation_status = 'error'
        validation_message = 'Error'
        name=request.data["name"]
        address=request.data["address"]
        survey_no=request.data["survey_no"]
        species_of_trees=request.data["tree_species"]

        tree_proposed=request.data["tree_proposed"]
        village=request.data["village"]
        district=request.data["district"]
        block=request.data["block"]
        taluka=request.data["taluka"]
        division=request.data["division"]
        area_range=request.data["area_range"]
        pincode=request.data["pincode"]
        spec_geo = request.data["spec_details"]
        print(spec_geo,'spec_geo')
        #spec_geo = request.data["log_details"]
        # print(request.FILES)
        ownership_proof_img=request.data["ownership_proof_img"]
        revenue_application_img=request.data["revenue_application_img"]
        revenue_approval_img=request.data["revenue_approval_img"]
        declaration_img=request.data["declaration_img"]
        location_sketch_img=request.data["location_sketch_img"]
        tree_ownership_img=request.data["tree_ownership_img"]
        aadhar_card_img=request.data["aadhar_card_img"]
        signature_img = request.data["signature_img"]
        lic_img=request.data["licence_img"]
        # tree_species=request.data["tree_species"]
        purpose = request.data["purpose_cut"]
        veh_reg=request.data["vehicel_reg"]
        driver_name= request.data["driver_name"]
        phone = request.data["phone"]
        mode = request.data["mode"]
        # log_details = request.data["log_details"]
        # trees_cutted = request.data["trees_cutted"]
        destination_address = request.data["destination_address"]
        destination_state = request.data["destination_state"]
        location_img1 = request.data["location_img1"]
        location_img2 = request.data["location_img2"]
        location_img3 = request.data["location_img3"]
        location_img4 = request.data["location_img4"]
        image1_lat = request.data["image1_lat"]
        image2_lat = request.data["image2_lat"]
        image3_lat = request.data["image3_lat"]
        image4_lat = request.data["image4_lat"]
        image1_log = request.data["image1_log"]
        image2_log = request.data["image2_log"]
        image3_log = request.data["image3_log"]
        image4_log = request.data["image4_log"]
        rangedetails = Range.objects.get(name=area_range)
        id2 = rangedetails.id
        revenue = RevenueOfficerdetail.objects.get(range_name_id=id2)
        print(revenue,'revenue valuesss')
        revenueid = revenue.Rev_user_id

        print("___________________________")
        url='static/media/'
        application = Applicationform.objects.create(is_form_two=True,
            name=name,address=address,destination_details=destination_address,destination_state=destination_state,
            survey_no=survey_no,village=village,total_trees=tree_proposed,
            district=district,pincode=pincode,species_of_trees=species_of_trees,
            purpose=purpose,block=block,taluka=taluka,division=division,appsecond_one_date = date.today(),
            area_range=area_range,by_user=request.user)
        print(application)
        saved_image=upload_product_image_file(application.id,aadhar_card_img,url,'AadharCard')
        saved_image_2=upload_product_image_file(application.id,revenue_approval_img,url,'RevenueApproval')
        saved_image_1=upload_product_image_file(application.id,declaration_img,url,'Declaration')
        saved_image_3=upload_product_image_file(application.id,revenue_application_img,url,'RevenueApplication')
        saved_image_4=upload_product_image_file(application.id,location_sketch_img,url,'LocationSketch')
        saved_image_5=upload_product_image_file(application.id,tree_ownership_img,url,'TreeOwnership')
        saved_image_6=upload_product_image_file(application.id,ownership_proof_img,url,'ProofOfOwnership')
        # saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')
        saved_image_8=upload_product_image_file(application.id,signature_img,url,'Signature')
        saved_image_9 = upload_product_image_file(application.id, location_img1, url, 'Location_img1')
        saved_image_10 = upload_product_image_file(application.id, location_img2, url, 'Location_img2')
        saved_image_11 = upload_product_image_file(application.id, location_img3, url, 'Location_img3')
        saved_image_12 = upload_product_image_file(application.id, location_img4, url, 'Location_img4')
        application.proof_of_ownership_of_tree=saved_image_6

                
        image_doc=image_documents.objects.create(app_form=application,
                revenue_approval=saved_image_2,declaration=saved_image_1,
                revenue_application=saved_image_3,location_sktech=saved_image_4,
                tree_ownership_detail=saved_image_5,aadhar_detail=saved_image,
                signature_img=saved_image_8,location_img1=saved_image_9,location_img2=saved_image_10,location_img3=saved_image_11,
                location_img4=saved_image_12,image1_lat=image1_lat,image2_lat=image2_lat,image3_lat=image3_lat,
                image4_lat=image4_lat,image1_log=image1_log,image2_log=image2_log, image3_log= image3_log, image4_log=image4_log
            )
        # application.revenue_approval = True
        # application.declaration = True
        application.verify_office = True
        application.application_status = 'P'
        application.reason_office = 'Recommended'
        application.approved_by_revenue_id = revenueid
        uid=request.user.id
        if destination_state!="Kerala":
            application.other_state = True
            # application.is_form_two = True

        
        application.application_no=generate_app_id(uid,application.id)
 #       application_no=generate_app_id(uid,application.id)
        #clprint(application_no,"*******************")
        application.signature_img = True
        application.revenue_application = True
        application.location_sktech = True
        application.tree_ownership_detail = True
        application.aadhar_detail = True
        application.save()
        saved_image_7 =""
        if lic_img!="":
            saved_image_7=upload_product_image_file(application.id,lic_img,url,'License')

#        tem = Applicationform.objects.filter(id = application.id).update(application_no=application_no,signature_img = True,revenue_application = True,location_sktech = True,tree_ownership_detail = True,aadhar_detail = True)
        # application.trees_cutted = True
        #print(")s",tem)
        tlog =[]
        # application.trees_cutted= True
        print(type(spec_geo))
        if spec_geo!="":
            for k in range(len(spec_geo)):


                #print(application,int(spec_geo[k]["species_of_tree"]))
                lat = spec_geo[k]["latitude"]
                lng= spec_geo[k]["longitude"]
                length= spec_geo[k]["length"]
                breadth= spec_geo[k]["breadth"]
                volume= spec_geo[k]["volume"]
                #spec_id = int(spec_geo[k]["species_of_tree"])
                spec_id = int(spec_geo[k]["Id"])
                spec = Species_geodetails(length=length,breadth=breadth,volume=volume,latitude=lat,longitude=lng,appform=application,species_tree_id=spec_id)
                tlog.append(spec)
                # tlog.append(Species_geodetails(latitude=lat,longitude=lng,appform_id=application.id,species_tree_id=spec_id))
            print(tlog)
        Species_geodetails.objects.bulk_create(tlog)

        # if log_details!="" : 
        #     for i in log_details:
        #         print(i)

        #         timber = Timberlogdetails(appform=application,species_of_tree=i["species_of_tree"], 
        #         length=i["length"], breadth=i["breadth"],volume=i["volume"],latitude=i["latitude"],longitude=i["longitude"])
        #         tlog.append(timber)
        #     Timberlogdetails.objects.bulk_create(tlog)

        vehicle = Vehicle_detials.objects.create(app_form=application,
            license_image=saved_image_7,vehicle_reg_no=veh_reg,
            driver_name=driver_name,driver_phone=phone,
            mode_of_transport=mode
            )
        validation_status = 'Success'
        validation_message = 'Data Saved Successfully.'   
        print(self.request.user.id)        
        return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)




class PhaseTwoFormtwo(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        app_id = request.data["app_id"]
        veh_reg=request.data["vehicel_reg"]
        driver_name= request.data["driver_name"]
        phone = request.data["phone"]
        mode = request.data["mode"]
        vehicle_detail = request.data["vehicle_detail"]
        log_details = request.data["log_details"]
        lic_img = request.data["lic_img"]
        trees_cutted = request.data["trees_cutted"]


        phasetwo = Applicationform.objects.filter(id=app_id).update(log_updated_by_user=True,trees_cutted=trees_cutted,appsecond_two_date=date.today())
        tlog = []
        if log_details!="" : 
            for i in log_details:
                print(i)

                timber = Timberlogdetails(appform_id=app_id,species_of_tree=i["species_of_tree"], 
                length=i["length"], breadth=i["breadth"],volume=i["volume"],latitude=i["latitude"],longitude=i["longitude"])
                tlog.append(timber)
            Timberlogdetails.objects.bulk_create(tlog)

        if vehicle_detail == True:

            chk_veh = Vehicle_detials.objects.filter(app_form_id=app_id)
            if chk_veh:
                saved_image_7 =""
                if lic_img!="":
                    saved_image_7=upload_product_image_file(app_id,lic_img,url,'License')

                Vehicle_detials.objects.filter(app_form_id=app_id).update(
                license_image=saved_image_7,vehicle_reg_no=veh_reg,
                driver_name=driver_name,driver_phone=phone,
                mode_of_transport=mode
                )

            else:
                saved_image_7 =""
                if lic_img!="":
                    saved_image_7=upload_product_image_file(app_id,lic_img,url,'License')
                vehicle = Vehicle_detials.objects.create(app_form_id=app_id,
                    license_image=saved_image_7,vehicle_reg_no=veh_reg,
                    driver_name=driver_name,driver_phone=phone,
                    mode_of_transport=mode
                    )

        validation_status = 'Success'
        validation_message = 'Form Two Data Submitted.'   
        return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)


class FormThree(APIView):

    permission_classes = [permissions.IsAuthenticated,]
 
    def post(self, request):
        app_id = request.data["app_id"]
        # spec_details=request.data["spec_details"]
        forest_sign = request.data["forest_sign"]
        marks= request.data["marks"]
        whence_obtained = request.data["whence_obtained"]
        destination = request.data["destination"]
        route = request.data["route"]
        
        time_allowed = request.data["time_allowed"]
        remarks = request.data["remarks"]
        sign_forest = ""
        
        if forest_sign!="":
            url='static/media/'
            sign_forest=form_three_upload_product_image_file(app_id,forest_sign,url,'Signature')

        phasetwo = Applicationform.objects.filter(id=app_id).update(form3_signature=sign_forest,form3_created_date=date.today(),is_form3=True,form3_created_by=request.user.id ,marks_form3=marks,whence_form3=whence_obtained,destination_form3=destination,route_form3=route,time_allowed_form3=time_allowed,remarks_form3=remarks)
        app_detail = Applicationform.objects.filter(id=app_id)
        if app_detail[0].other_state==False:
            qr_code=get_qr_code(app_id)
            print(qr_code,'-----QR')
            qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
            print(qr_img,'----qr_path')
            is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
            if is_timber:
                for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
                    log_qr_code=get_log_qr_code(app_id,each_timber['id'])
                    print(log_qr_code,'-----LOG QR')

                    log_data='Log Details:\n'
                    log_data+='Application No. :-'+app_detail[0].application_no+'\n'
                    log_data+='Destination :-'+app_detail[0].destination_details+'\n'
                    log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
                    log_data+='Length :-'+str(each_timber['length'])+'\n'
                    log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
                    log_data+='Volume :-'+str(each_timber['volume'])+'\n'
                    log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
                    log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
                    log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
                    print(log_qr_img,'----qr_path')
                    is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img)
            transit_pass=TransitPass.objects.create(
                                    state = app_detail[0].state,
                                    district = app_detail[0].district,
                                    taluka = app_detail[0].taluka,
                                    block = app_detail[0].block,
                                    village = app_detail[0].village,
                                    qr_code = qr_code,
                                    qr_code_img =qr_img, 
                                    app_form_id = app_id
                                )
            app_detail.update(
                                #reason_range_officer = remarks ,
                                application_status = 'A',
                                approved_by = request.user,
                                verify_range_officer = True,
                                range_officer_date = date.today(),
                                transit_pass_id=transit_pass.id,
                                transit_pass_created_date = date.today(),
                                )
        else:
              if app_detail[0].division_officer==True:
                  qr_code=get_qr_code(app_id)
                  print(qr_code,'-----QR')
                  qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
                  print(qr_img,'----qr_path')
                  is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
                  if is_timber:
                      for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
                          log_qr_code=get_log_qr_code(app_id,each_timber['id'])
                          print(log_qr_code,'-----LOG QR')
      
                          log_data='Log Details:\n'
                          log_data+='Application No. :-'+app_detail[0].application_no+'\n'
                          log_data+='Destination :-'+app_detail[0].destination_details+'\n'
                          log_data+='Species Name :-'+each_timber['species_of_tree']+'\n'
                          log_data+='Length :-'+str(each_timber['length'])+'\n'
                          log_data+='Girth :-'+str(each_timber['breadth'])+'\n'
                          log_data+='Volume :-'+str(each_timber['volume'])+'\n'
                          log_data+='Latitude :-'+str(each_timber['latitude'])+'\n'
                          log_data+='Longitude :-'+str(each_timber['longitude'])+'\n'
                          log_qr_img=generate_log_qrcode_image(log_qr_code, settings.QRCODE_PATH, each_timber['id'],log_data)
                          print(log_qr_img,'----qr_path')
                          is_timber.filter(id=each_timber['id']).update(log_qr_code=log_qr_code,log_qr_code_img=log_qr_img)
                  transit_pass=TransitPass.objects.create(
                                          state = app_detail[0].state,
                                          district = app_detail[0].district,
                                          taluka = app_detail[0].taluka,
                                          block = app_detail[0].block,
                                          village = app_detail[0].village,
                                          qr_code = qr_code,
                                          qr_code_img =qr_img, 
                                          app_form_id = app_id
                                      )
                  app_detail.update(
                                      #reason_range_officer = remarks ,
                                      application_status = 'A',
                                      approved_by = request.user,
                                      verify_range_officer = True,
                                      range_officer_date = date.today(),
                                      transit_pass_id=transit_pass.id,
                                      transit_pass_created_date = date.today(),
                                      )
              else:
                  validation_status = 'Error'
                  validation_message = 'Form Three Data Not Submitted.'   
                  return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)
        validation_status = 'Success'
        validation_message = 'Form Three Data Submitted.'   
        return JsonResponse({'status': validation_status, 'message': validation_message} , safe=False)



class FormTwoAssignDeputy(APIView):
    permission_classes = [permissions.IsAuthenticated,]


    def post(self,request):
        groups=request.user.groups.values_list('name',flat = True)
        app_id = request.data["app_id"]
        application_detail = Applicationform.objects.filter(id=app_id)

        deputy_id = request.data["deputy_id"]
        if groups[0] != "forest range officer":
            return JsonResponse({'message':'Only Forest Range Officer is allowed.'})
        else:
            if application_detail[0].log_updated_by_user:
                assigned_deputy2 = deputy_id
                assigned_deputy2_by = request.user.id
                assigned_deputy2_date = datetime.today()
                temp = Applicationform.objects.filter(id = app_id).update(assigned_deputy2 = assigned_deputy2,assigned_deputy2_by = request.user.id,assigned_deputy2_date = assigned_deputy2_date)
                return JsonResponse({'message':'Successfully Assigned Deputy'})

            else:
                assigned_deputy1 = deputy_id
                assigned_deputy1_by = request.user.id
                assigned_deputy1_date = datetime.today()
                temp = Applicationform.objects.filter(id = app_id).update(assigned_deputy1 = assigned_deputy1,assigned_deputy1_by = request.user.id,assigned_deputy1_date = assigned_deputy1_date)
                return JsonResponse({'message':'Successfully Assigned Deputy'})

class new_approve_transit_pass(APIView):
    permission_classes = [permissions.IsAuthenticated,]


    def post(self,request):
        app_id = request.data["app_id"]
        application_detail = Applicationform.objects.filter(id=app_id)
        groups=request.user.groups.values_list('name',flat = True)
        reason = request.data["reason"]
        if application_detail:
            if application_detail[0].application_status=='R':
                return JsonResponse({'message':'Action cannot be taken, Once Application rejected!'})
        else:
            return JsonResponse({'message':'Bad Request!'})
        if request.data["type"] == 'REJECT':
            print(reason,'--reason')

            if groups[0] == "revenue officer":
                application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                disapproved_by=request.user.id,disapproved_by_grp="By Revenue Officer",
                    application_status='R',verify_office = True,verify_office_date = date.today())
            elif groups[0] == "deputy range officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].verify_office==True:
                    if application_detail[0].is_form_two ==False:
                        application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                        disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
                                application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
                    else:
                        if application_detail[0].verify_deputy2 == True:
                            application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                            disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
                            application_status='R',verify_deputy2 = True,deputy2_date = date.today())
                        else:
                            print("from Heree@@@@@@@@@@@@@@@")
                            application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                            disapproved_by=request.user.id,disapproved_by_grp="By Deputy Officer",
                            application_status='R',depty_range_officer = True,deputy_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Revenue Officer Action is Pending !'})
                # pass
            elif groups[0] == "forest range officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].depty_range_officer==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Forest Officer",
                    application_status='A',verify_range_officer = True,range_officer_date = date.today(),division_officer = True,division_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Deputy Officer Action is Pending !'})

                # pass


            elif groups[0] == "division officer":
                # application_detail = Applicationform.objects.filter(id=app_id)
                if application_detail[0].verify_range_officer==True:
                    application_form = Applicationform.objects.filter(id=app_id).update(disapproved_reason=reason,
                    disapproved_by=request.user.id,disapproved_by_grp="By Division Officer",
                    application_status='R',division_officer = True,division_officer_date = date.today())
                else:
                    JsonResponse({'message':'Application cannot be disapproved as Forest Range Officer Action is Pending !'})
                # pass
            else:
                pass
            return JsonResponse({'message':'Application has been disapproved!'})
            # return render(request,"my_app/tigram/application_details.html",{'applicant':APPLICATION,'applications':application_detail,'message':'Application has been disapproved!'})

        vehicle_detail = Vehicle_detials.objects.filter(app_form_id=app_id)
        # transit_pass = TransitPass.object.filter(app_form_id=app_id)
        if application_detail :

            reason=request.data['reason']
            if groups[0] == "revenue officer":
                application_detail.update(
                reason_office = reason,
                application_status = 'P',
                approved_by_revenue = request.user,
                verify_office = True,
                verify_office_date = date.today(),
                # transit_pass_id=transit_pass.id,
                # transit_pass_created_date = datetime.date.today(),
                )
            elif groups[0] == "deputy range officer":
          			if application_detail[0].verify_office==True:
          				if application_detail[0].is_form_two==True:
          					if application_detail[0].verify_deputy2==False:
          						application_detail.update(
          						reason_deputy2 = reason ,
          						application_status = 'P',
          						approved_by_deputy2 = request.user,
          						verify_deputy2 = True,
          						deputy2_date = date.today())
          					else:
          						if application_detail[0].verify_forest1==False:
          							JsonResponse({'message':'Application cannot be approved as Forest Range Officer Approval is Pending for Trees Cutting!'})
          						application_detail.update(
          						reason_depty_ranger_office = reason ,
          						application_status = 'P',
          						approved_by_deputy = request.user,
          						depty_range_officer = True,
          						deputy_officer_date = date.today(),
          						)
          				else:
          					application_detail.update(
          					reason_depty_ranger_office = reason ,
          					application_status = 'P',
          					approved_by_deputy = request.user,
          					depty_range_officer = True,
          					deputy_officer_date = date.today(),
          
          					)
          			else:
          				JsonResponse({'message':'Application cannot be approved as Revenue Officer Approval is Pending !'})
            # if vehicle_detail:
            elif groups[0] == "forest range officer":
              			print('-forest---')
              			if application_detail[0].is_form_two==False :
              				print('-forest formFalse---')
              				if application_detail[0].depty_range_officer==True:
              					print('-forest formFalse depty True---')
              					if application_detail[0].other_state == False:
              						qr_code=get_qr_code(app_id)
              						print(qr_code,'-----QR')
              						qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
              						print(qr_img,'----qr_path')
              						is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
              						if is_timber:
              							for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
              								log_qr_code=get_log_qr_code(app_id,each_timber['id'])
              								print(log_qr_code,'-----LOG QR')
              
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
              								print(log_qr_img,'----qr_path')
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
              							reason_range_officer = reason ,
              							application_status = 'A',
              							approved_by = request.user,
              							verify_range_officer = True,
              							range_officer_date = date.today(),
              							transit_pass_id=transit_pass.id,
              							transit_pass_created_date = date.today(),
              							)
              					else:
              						application_detail.update(
              						reason_range_officer = reason ,
              						application_status = 'P',
              						approved_by = request.user,
              						verify_range_officer = True,
              						range_officer_date = date.today(),
              						)
              						# JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
              				# application_detail[0].save()
              				else:
              
              						JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
              			else:
              				print('-forest formtwo true---')
              				if application_detail[0].is_form3==False:
              					print('-forest form3 false---')
              					
              					if application_detail[0].depty_range_officer==True:
              						print('-forest form3 false depty1 true---')
              						application_detail.update(
              							reason_range_officer = reason ,
              							application_status = 'P',
              							approved_by = request.user,
              							verify_range_officer = True,
              							range_officer_date = date.today(),
              								)
              					elif application_detail[0].verify_deputy2==True:
              						# if 
              						print('-forest form3 false depty2 true---')
              						application_detail.update(
              								reason_forest1 = reason ,
              								application_status = 'P',
              								approved_by_forest1 = request.user,
              								verify_forest1 = True,
              								forest1_date = date.today(),
              								)
              					else:
              						JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
              				else:
              					print('-forest form2 true--- form3 true---')
              					pass
              				# pass              		
            elif groups[0] == "division officer":
                if application_detail[0].verify_range_officer==True:
                    if application_detail[0].other_state == True:
                        if application_detail[0].is_form_two== True:
                              application_detail.update(
                                reason_division_officer = reason ,
                                approved_by_division = request.user,
                                division_officer = True,
                                division_officer_date = date.today(),
                                )
                              return JsonResponse({'message':'Application has been approved!'})
                        qr_code=get_qr_code(app_id)
                        print(qr_code,'-----QR')
                        qr_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, app_id)
                        print(qr_img,'----qr_path')
                        is_timber = Timberlogdetails.objects.filter(appform_id=app_id)
                        if is_timber:
                            for each_timber in is_timber.values('id','species_of_tree','latitude','longitude','length','breadth','volume'):
                                log_qr_code=get_log_qr_code(app_id,each_timber['id'])
                                print(log_qr_code,'-----LOG QR')

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
                                print(log_qr_img,'----qr_path')
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
                            reason_division_officer = reason ,
                            application_status = 'A',
                            approved_by_division = request.user,
                            division_officer = True,
                            division_officer_date = date.today(),
                            transit_pass_id=transit_pass.id,
                            transit_pass_created_date = date.today(),
                            )
                    else:
                        JsonResponse({'message':'Application cannot be approved !'})
                        # JsonResponse({'message':'Application cannot be approved as Deputy Range Officer Approval is Pending !'})
                # application_detail[0].save()
                else:
                    JsonResponse({'message':'Application cannot be approved as Forest Range Officer Approval is Pending !'})
            else:
                pass
        return JsonResponse({'message':'Application has been approved!'})



class TreeSpeciesList(APIView):

    permission_classes = [permissions.AllowAny,]
 
    def get(self, request):

        application_detail = list(TreeSpecies.objects.filter(is_noc=False).values())
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'   
        return JsonResponse({'status': validation_status, 'message': validation_message,'data':application_detail} , safe=False)


class need_field_verification(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        app_id = request.data['app_id']
        print(app_id,'app_id')
        # application_detail = list(Range.objects.filter(division__name__iexact=range_area).values('name'))
        # application_detail = list(Applicationform.objects.filter().values())
        field = Applicationform.objects.filter(id=app_id).update(location_needed="True")

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message})

class success_field_verification(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        app_id = request.data['app_id']

        field = Applicationform.objects.filter(id=app_id).update(status="success")

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message})


class failed_field_verification(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        app_id = request.data['app_id']

        field = Applicationform.objects.filter(id=app_id).update(status="failed")

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message})

class scaned_details(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        app_form_id = request.data['app_form_id']
        checkpost_officer_id = request.data["checkpost_officer_id"]
        print(checkpost_officer_id,'checkpost_officer_id')
        check_log = request.data['check_lat']
        check_lat = request.data['check_log']
        remark = request.data['remark']
        user_group= request.data['user_group']

        if user_group== 'checkpost officer':
            checkpost_data = CheckPostOfficerdetail.objects.get(check_user_id=checkpost_officer_id)
            checkpost_id = checkpost_data.checkpost_id
            if CustomUser.objects.filter(id=checkpost_officer_id):
                if ScanedDetails_View.objects.filter(app_form_id=app_form_id,checkpost_officer_id=checkpost_officer_id):
                    user_data=ScanedDetails_View.objects.filter(app_form_id=app_form_id)
                    for i in user_data:
                        if i.user_group =='user':
                            validation_status = 'Failed'
                            validation_message = 'User Allready Scaned.'
                            return JsonResponse({'status': validation_status, 'message': validation_message})
                        else:
                            pass
                    validation_status = 'Failed'
                    validation_message = 'Duplicate value enterd.'
                    return JsonResponse({'status': validation_status, 'message': validation_message})
                else:

                    if ScanedDetails_View.objects.filter(app_form_id=app_form_id):
                        user_data = ScanedDetails_View.objects.filter(app_form_id=app_form_id)
                        for i in user_data:
                            if i.user_group == 'user':
                                validation_status = 'Failed'
                                validation_message = 'User Allready Scaned.'
                                return JsonResponse({'status': validation_status, 'message': validation_message})
                            else:
                                pass

                        scan_detail = ScanedDetails_View.objects.create(app_form_id=app_form_id,
                                                                        checkpost_officer_id=checkpost_officer_id,checkpost_id=checkpost_id,
                                                                        check_log=check_log, check_lat=check_lat,remark=remark,user_group=user_group)
                        scan_detail.save()
                        validation_status = 'Success'
                        validation_message = 'Data Fetched Successfully.'
                        return JsonResponse({'status': validation_status, 'message': validation_message})
                    else:
                        scan_detail = ScanedDetails_View.objects.create(app_form_id=app_form_id,
                                                                        checkpost_officer_id=checkpost_officer_id,
                                                                        checkpost_id=checkpost_id,
                                                                        check_log=check_log, check_lat=check_lat,
                                                                        remark=remark, user_group=user_group)
                        scan_detail.save()
                        validation_status = 'Success'
                        validation_message = 'Data Fetched Successfully.'
                        return JsonResponse({'status': validation_status, 'message': validation_message})

            else:
                validation_status = 'Invalid officer'
                validation_message = 'Failed.'
                return JsonResponse({'status': validation_status, 'message': validation_message})
        else:
            if CustomUser.objects.filter(id=checkpost_officer_id):
                if ScanedDetails_View.objects.filter(app_form_id=app_form_id,
                                                     checkpost_officer_id=checkpost_officer_id):
                    user_data = ScanedDetails_View.objects.filter(app_form_id=app_form_id)
                    for i in user_data:
                        if i.user_group =='user':
                            validation_status = 'Failed'
                            validation_message = 'User Allready Scaned.'
                            return JsonResponse({'status': validation_status, 'message': validation_message})
                        else:
                            pass

                    validation_status = 'Failed'
                    validation_message = 'Duplicate value enterd.'
                    return JsonResponse({'status': validation_status, 'message': validation_message})
                else:
                    if ScanedDetails_View.objects.filter(app_form_id=app_form_id):
                        user_data = ScanedDetails_View.objects.filter(app_form_id=app_form_id)
                        for i in user_data:
                            if i.user_group == 'user':
                                validation_status = 'Failed'
                                validation_message = 'User Allready Scaned.'
                                return JsonResponse({'status': validation_status, 'message': validation_message})
                            else:
                                pass
                        scan_detail = ScanedDetails_View.objects.create(app_form_id=app_form_id,
                                                                        checkpost_officer_id=checkpost_officer_id,

                                                                        check_log=check_log, check_lat=check_lat,                                                                        remark=remark,user_group=user_group)
                        scan_detail.save()
                        validation_status = 'Success'
                        validation_message = 'Data Fetched Successfully.'
                        return JsonResponse({'status': validation_status, 'message': validation_message})
                    else:
                        scan_detail = ScanedDetails_View.objects.create(app_form_id=app_form_id,
                                                                        checkpost_officer_id=checkpost_officer_id,

                                                                        check_log=check_log, check_lat=check_lat,
                                                                        remark=remark, user_group=user_group)
                        scan_detail.save()
                        validation_status = 'Success'
                        validation_message = 'Data Fetched Successfully.'
                        return JsonResponse({'status': validation_status, 'message': validation_message})
            else:
                validation_status = 'Invalid officer'
                validation_message = 'Failed.'
                return JsonResponse({'status': validation_status, 'message': validation_message})



class ScanedListApplication(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):
        groups = request.user.groups.values_list('name', flat=True)

        if groups[0] == 'checkpost officer':
            officer_range = ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id)
            for i in officer_range:
                application_no=i.app_form.application_no
                print(application_no,'application_no')

                print(officer_range,'officer_range')
                if officer_range != '':

                    application_detail = list(
                        ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id).values()
                        )

                    print(application_detail,'application_detail')

        # application_detail = list(Applicationform.objects.filter().values())

            validation_status = 'Success'
            validation_message = 'Data Feteched Successfully.'
            return JsonResponse({'status': validation_status, 'message': validation_message, 'data': application_detail}, safe=False)
        else:
            officer_range = ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id)
            for i in officer_range:
                application_no = i.app_form.application_no
                print(application_no, 'application_no')

                print(officer_range, 'officer_range')
                if officer_range != '':
                    application_detail = list(
                        ScanedDetails_View.objects.filter(checkpost_officer_id=request.user.id).values()
                    )

                    print(application_detail, 'application_detail')

            # application_detail = list(Applicationform.objects.filter().values())

            validation_status = 'Success'
            validation_message = 'Data Feteched Successfully.'
            return JsonResponse(
                {'status': validation_status, 'message': validation_message, 'data': application_detail}, safe=False)

class Add_Timber_Details(APIView):

    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        user_id = request.user.id
        name = request.data["name"]
        address = request.data["address"]
        phone = request.data["phone"]
        timber_name = request.data["timber_name"]
        division = request.data["division"]
        quantity = request.data["quantity"]
        dist = request.data["dist"]
        timber_img = request.data["timber_image"]
        print(timber_img,'timber_img')
        url = 'media/'
        timber_image = timber_image_file(user_id,timber_img,url,'TimberImage')
        print(timber_image,'timber_image')
        timber = Buyer_Seller.objects.create(
            address=address,
            name=name,
            phone=phone,
            timber_image=timber_image,
            timber_name=timber_name,
            division=division,
            quantity=quantity,
            dist=dist,
            by_user_id=request.user.id
        )
        validation_status = 'Success'
        validation_message = 'Data Saved Successfully.'
        # print(self.request.user.id)
        return JsonResponse({'status': validation_status, 'message': validation_message}, safe=False)

class failed_field_verification(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        app_id = request.data['app_id']

        field = Applicationform.objects.filter(id=app_id).update(status="failed")

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message})

class Buyer_Seller_Add_Data(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):

        groups = request.user.groups.values_list('name', flat=True)
        photo_url = str(settings.SERVER_BASE_URL)+ str(settings.TIMBER_IMAGE)
        add_data = list(Buyer_Seller.objects.filter(by_user_id=request.user.id, status="active",selected=False).values().annotate(
            timber_url=Concat(Value(photo_url), 'timber_image',output_field=CharField())))
        # all_data = Buyer_Seller.objects.filter(status="active").exclude(by_user_id=request.user.id)
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse(
            {'status': validation_status, 'message': validation_message, 'data': add_data}, safe=False)

class View_Buyer_Requirement(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):

        groups = request.user.groups.values_list('name', flat=True)

        add_data = list(Buyer_Requirement.objects.filter(by_user_id=request.user.id, status="active").values())
        # all_data = Buyer_Seller.objects.filter(status="active").exclude(by_user_id=request.user.id)
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse(
            {'status': validation_status, 'message': validation_message, 'data': add_data}, safe=False)

class Buyer_Seller_All_Data(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        photo_url = settings.SERVER_BASE_URL + settings.TIMBER_IMAGE
        all_data = list(Buyer_Seller.objects.filter(status="active", selected=False).exclude(by_user_id=request.user.id).values().annotate(
            timber_url=Concat(Value(photo_url), 'timber_image',output_field=CharField())))
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse(
            {'status': validation_status, 'message': validation_message, 'data': all_data}, safe=False)

class View_All_BuyerRequirement(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        all_data = list(Buyer_Requirement.objects.filter(status="active").values())
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse(
            {'status': validation_status, 'message': validation_message, 'data': all_data}, safe=False)

class Delete_Timber_Data(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        id = request.data['id']

        field = Buyer_Seller.objects.filter(id=id).update(status="delete")

        validation_status = 'Success'
        validation_message = 'Deleted  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message})


class ListRange(APIView):
    permission_classes = [permissions.AllowAny, ]

    def get(self, request):
        application_detail = list(Division.objects.filter(is_delete=False).values('name'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message, 'data': application_detail},
                            safe=False)


class UpdateLocationImage(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):
        app_id = request.data['app_id']
        location_img1 = request.data["location_img1"]
        location_img2 = request.data["location_img2"]
        location_img3 = request.data["location_img3"]
        location_img4 = request.data["location_img4"]
        image1_lat = request.data["image1_lat"]
        image2_lat = request.data["image2_lat"]
        image3_lat = request.data["image3_lat"]
        image4_lat = request.data["image4_lat"]
        image1_log = request.data["image1_log"]
        image2_log = request.data["image2_log"]
        image3_log = request.data["image3_log"]
        image4_log = request.data["image4_log"]
        application_detail = Applicationform.objects.get(id=app_id)
        application_detail.application_status='P'
        application_detail.save()

        location_image=image_documents.objects.get(app_form_id=app_id)
        url = 'static/media/upload/license/'
        saved_image_9 = upload_product_image_file(application_detail.id, location_img1, url, 'Location_img1')
        saved_image_10 = upload_product_image_file(application_detail.id, location_img2, url, 'Location_img2')
        saved_image_11 = upload_product_image_file(application_detail.id, location_img3, url, 'Location_img3')
        saved_image_12 = upload_product_image_file(application_detail.id, location_img4, url, 'Location_img4')
        location_image.location_img1=saved_image_9
        location_image.location_img2=saved_image_10
        location_image.location_img3=saved_image_11
        location_image.location_img4=saved_image_12
        location_image.image1_lat=image1_lat
        location_image.image2_lat=image2_lat
        location_image.image3_lat=image3_lat
        location_image.image4_lat=image4_lat
        location_image.image1_log=image1_log
        location_image.image2_log=image2_log
        location_image.image3_log=image3_log
        location_image.image4_log=image4_log
        location_image.save()
        message = 'Vehicles details updated successfully!'

        return JsonResponse({'status': 'Success', 'message': message})

class Select_Data(APIView):
    permission_classes = [permissions.AllowAny, ]
    def post(self, request):
        id = request.data['id']
        data = Buyer_Seller.objects.filter(id=id).update(selected=True)
        validation_status = 'Success'
        validation_message = 'Selected  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message})

class Add_Requirement(APIView):

    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        id = request.data['id']
        name = request.data["name"]
        address = request.data["address"]
        phone = request.data["phone"]
        timber_name = request.data["timber_name"]
        division = request.data["division"]
        quantity = request.data["quantity"]
        dist = request.data["dist"]
        timber = Buyer_Requirement.objects.create(
            address=address,
            name=name,
            phone=phone,
            timber_name=timber_name,
            division=division,
            quantity=quantity,
            dist=dist,
            by_user_id=id
        )
        validation_status = 'Success'
        validation_message = 'Data Saved Successfully.'
        # print(self.request.user.id)
        return JsonResponse({'status': validation_status, 'message': validation_message}, safe=False)

class Firm_Registration(APIView):

    permission_classes = [permissions.IsAuthenticated, ]

    def post(self, request):
        user = CustomUser.objects.get(id=request.user.id)
        if request.method == 'POST':
            id = request.data['id']
            organization = request.data["organization"]
            pan_card = request.data["pan_card"]
            gst = request.data["gst"]
            cin_number = request.data["cin_number"]
            tan_number = request.data["tan_number"]
            website = request.data["website"]
            service_tax = request.data["service_tax"]
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
            validation_status = 'Success'
            validation_message = 'Data Saved Successfully.'
            return JsonResponse({'status': validation_status, 'message': validation_message}, safe=False)

class check_usr_category(APIView):
    permission_classes = [permissions.AllowAny,]
    def post(self, request):
        id = request.data['id']
        data = list(CustomUser.objects.filter(id=id).values('usr_category'))
        validation_status = 'Success'
        validation_message = 'Selected  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message,'data': data})

class Buyer_SelectedDta(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        all_data = list(Buyer_Seller.objects.filter(status="active", selected=True).values())
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse(
            {'status': validation_status, 'message': validation_message, 'data': all_data}, safe=False)

class SellerView_SelectedDta(APIView):
    permission_classes = [permissions.IsAuthenticated, ]

    def get(self, request):
        groups = request.user.groups.values_list('name', flat=True)
        all_data = list(Buyer_Seller.objects.filter(by_user_id=request.user.id, status="active", selected=True).values())
        validation_status = 'Success'
        validation_message = 'Data Feteched Successfully.'
        return JsonResponse(
            {'status': validation_status, 'message': validation_message, 'data': all_data}, safe=False)

class requirement_division_filtration(APIView):
    permission_classes = [permissions.AllowAny,]
    def post(self, request):
        division = request.data['division']
        data = list(Buyer_Requirement.objects.filter(division=division).values())
        validation_status = 'Success'
        validation_message = 'Selected  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message,'data': data})

class addtimber_division_filtration(APIView):
    permission_classes = [permissions.AllowAny,]
    def post(self, request):
        division = request.data['division']
        data = list(Buyer_Seller.objects.filter(division=division).values())
        validation_status = 'Success'
        validation_message = 'Selected  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message,'data': data})

class requirement_district_species_filtration(APIView):
    permission_classes = [permissions.AllowAny,]
    def post(self, request):
        district = request.data['district']
        species = request.data['species']
        if district=="" and species=="":
            data = list(Buyer_Requirement.objects.all(dist=district).values())
        elif district=="" and species!="":
            data = list(Buyer_Requirement.objects.filter(timber_name=species).values())
        elif district!="" and species=="":
            data = list(Buyer_Requirement.objects.filter(dist=district).values())
        else:
            data = list(Buyer_Requirement.objects.filter(dist=district,timber_name=species).values())
        validation_status = 'Success'
        validation_message = 'Selected  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message,'data': data})


class addtimber_district_species_filtration(APIView):
    permission_classes = [permissions.AllowAny,]
    def post(self, request):
        district = request.data['district']
        species = request.data['species']
        if district=="" and species=="":
            data = list(Buyer_Seller.objects.all(dist=district).values())
        elif district=="" and species!="":
            data = list(Buyer_Seller.objects.filter(timber_name=species).values())
        elif district!="" and species=="":
            data = list(Buyer_Seller.objects.filter(dist=district).values())
        else:
            data = list(Buyer_Seller.objects.filter(dist=district,timber_name=species).values())
        validation_status = 'Success'
        validation_message = 'Selected  Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message,'data': data})


class LoadTreeSpecies(APIView):
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        application_detail = list(TreeSpecies.objects.all().values('name'))
        # application_detail = list(Applicationform.objects.filter().values())

        validation_status = 'Success'
        validation_message = 'Data Fetched Successfully.'
        return JsonResponse({'status': validation_status, 'message': validation_message, 'data': application_detail},
                            safe=False)

class table_eleven(APIView):
    permission_classes = [AllowAny]

    def get(self,request):
        context = {}
        applica = ScanedDetails_View.objects.all().values('checkpost_officer__name','scan_date','app_form__created_date','app_form__transit_pass_id','app_form__application_no','checkpost__checkpost_name')
        context['applicantions'] = list(applica)
        return JsonResponse(context,safe=False)


class register_otp_verification(APIView):
    # Allow any user (authenticated or not) to access this url
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        mobile = request.data["phone"]
        data = CustomUser.objects.filter(phone=mobile)
        if data:
            current_time = datetime.now()
            otp = new_otp_generateOTP()
            print(current_time, 'current_time')
            CustomUser.objects.filter( phone=mobile).update(mobile_otp=otp,no_of_attempts_register='0',mobile_otp_created_time=current_time)
            
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
              return JsonResponse({'status': 'success', 'applications':'Exceded daily limit'}, safe=False)
            new_sendSingleSMS(USERNAME, PASSWORD, SENDERID, message, mobile, templateid, key)
            validation_message = 'Success'
            return JsonResponse({'status': 'success', 'message': validation_message}, safe=False)
        validation_message = 'Please try again or Please verify your registered email or phone number with admin'
        return JsonResponse({'status': 'error', 'message': validation_message}, safe=False)
        # return JsonResponse({'status': validation_status, 'message': validation_message,"data":data} , safe=False)


class register_Otp_verify(APIView):
    # Allow any user (authenticated or not) to access this url
    permission_classes = [permissions.AllowAny, ]
    def post(self, request):
        phone = request.data["phone"]
        otp= request.data["otp"]
        user_Exist = CustomUser.objects.filter(phone=phone, mobile_otp=otp)
        if user_Exist:
            data = CustomUser.objects.get(phone=phone, mobile_otp=otp)
            db_time = data.mobile_otp_created_time
            datetime_obj = datetime.strptime(db_time, '%Y-%m-%d %H:%M:%S.%f')
            print(type(datetime_obj), 'datetime_obj')
            print(datetime_obj, 'datetime_obj')
            now = datetime.now()
            print(now, 'now')
            print(type(now), "now")
            time_difference = now - datetime_obj
            if time_difference > timedelta(minutes=3):
                validation_message = 'OTP expired'
                return JsonResponse({'status': 'error', 'message': validation_message}, safe=False)
            else:
                CustomUser.objects.filter(phone=phone).update(mobile_verified='True')
                validation_message = "Registered successfully"
                return JsonResponse({'status': 'success', 'message': validation_message}, safe=False)
        else:
            user_Existt = CustomUser.objects.get(phone=phone)
            print(user_Existt, 'user_Existt')
            attempts = user_Existt.no_of_attempts_register
            val = int(attempts)
            val = val + 1
            CustomUser.objects.filter(phone=phone).update(no_of_attempts_register=val)
            if val > 3:
                validation_message = "You execeded the limit please try after sometime"
                return JsonResponse({'status': 'error', 'message': validation_message}, safe=False)
            else:
                validation_message = "Invalid OPT"
                return JsonResponse({'status': 'error', 'message': validation_message}, safe=False)



class set_newpassword(APIView):
    # Allow any user (authenticated or not) to access this url
    permission_classes = [permissions.AllowAny, ]
    def post(self, request):
        passwd = request.data["npass"]
        passwd1 = request.data["rpass"]
        phone = request.data["phone"]
        print(passwd, "****121212**************")
        isuser = CustomUser.objects.filter(phone=phone)
        if passwd == passwd1:
            if isuser:
                # isuser.set_password(passwd)
                new_password = make_password(passwd)
                isuser.update(password=new_password)
                validation_message = "Password Changed Successfully"
                return JsonResponse({'status': 'success', 'message': validation_message}, safe=False)
        else:
            validation_message = "Password not changed"
            return JsonResponse({'status': 'error', 'message': validation_message}, safe=False)



class get_villages(APIView):
    permission_classes = [permissions.AllowAny, ]
    #permission_classes = [permissions.AllowAny, ]
    def get(self, request):
        villages = Village.objects.all()
        v = VillageSerializer(villages, many=True)
        return JsonResponse({'status': 'success', 'villages': v.data}, safe=False)
    def post(self, request):
     selected_village = request.data['village']
     context = {} 
     v = Village.objects.get(village_name=selected_village)
     context['village_name'] = v.village_name
     context['village_taluka'] = v.taluka.taluka_name
     t = Taluka.objects.get(taluka_name=context['village_taluka'])
     context['village_dist'] = t.dist.district_name
     context['possibility'] = TempSerializer(TempLinkage.objects.filter(village=v.village_name) , many=True).data
     return JsonResponse({'status': 'success', 'data': context}, safe=False)
        


class get_transit_details(APIView):
  permission_classes = [permissions.AllowAny, ]
  def post(self, request):
    try:
     context = {}
     context['application_details']  = ApplicationSerializer(Applicationform.objects.get(application_no=request.data['transit_num'])).data
     context['log_details'] =  TimberSerializer(Timberlogdetails.objects.filter(appform_id= context['application_details']['id']) ,many =True).data
     context['img_details'] =  ImageSerial(image_documents.objects.get(app_form= context['application_details']['id'])).data  
     if context['application_details']['application_status']== "A":
      print("okay")
      return JsonResponse({'status': 'success', 'data': context}, safe=False)
     else :
         return JsonResponse({'status': 'error', 'message': "Cutting pass not yet approved"}, safe=False)    
    except:
        return JsonResponse({'status': 'error', 'message': "Cutting pass does not exist"}, safe=False)   
    


class deputy_field_verify(APIView):
    #permission_classes = [permissions.IsAuthenticated,]
    permission_classes = [permissions.AllowAny,]
 
    def post(self, request):
        try:
         app_id = request.data['app_id']
         c = Applicationform.objects.get(id = app_id)
         print(request.user.id)
         print(c.d)
         if c.d == request.user:
             print("OKAY")
             pass
         elif c.f_r == request.user:
             print("OKAY")
             pass
         else: 
            raise Exception("Not authorized to Filed verification")
         location_img1 = request.data["location_img1"]
         location_img2 = request.data["location_img2"]
         location_img3 = request.data["location_img3"]
         location_img4 = request.data["location_img4"]
         image1_lat = request.data["image1_lat"]
         image2_lat = request.data["image2_lat"]
         image3_lat = request.data["image3_lat"]
         image4_lat = request.data["image4_lat"]
         image1_log = request.data["image1_log"]
         image2_log = request.data["image2_log"]
         image3_log = request.data["image3_log"]
         image4_log = request.data["image4_log"]
         log_details = request.data['log_details']
         application_detail = Applicationform.objects.filter(id=app_id)
         location_image=image_documents.objects.get(app_form_id=app_id)
         url = 'static/media/upload/license/'
         saved_image_9 = dep_upload_product_image_file(application_detail[0].id, location_img1, url, 'Location_img1')
         saved_image_10 = dep_upload_product_image_file(application_detail[0].id, location_img2, url, 'Location_img2')
         saved_image_11 = dep_upload_product_image_file(application_detail[0].id, location_img3, url, 'Location_img3')
         saved_image_12 = dep_upload_product_image_file(application_detail[0].id, location_img4, url, 'Location_img4')
         location_image.location_img1=saved_image_9
         location_image.location_img2=saved_image_10
         location_image.location_img3=saved_image_11
         location_image.location_img4=saved_image_12
         location_image.image1_lat=image1_lat
         location_image.image2_lat=image2_lat
         location_image.image3_lat=image3_lat
         location_image.image4_lat=image4_lat
         location_image.image1_log=image1_log
         location_image.image2_log=image2_log
         location_image.image3_log=image3_log
         location_image.image4_log=image4_log
         location_image.save()
         tlog = []
         print(log_details)
         if log_details != "":
            for i in log_details:
                print(i)
                timber = ApprovedTimberLog(appform=application_detail[0], species_of_tree=i["species_of_tree"],length=i["length"], breadth=i["breadth"], volume=i["volume"])
                tlog.append(timber)
            ApprovedTimberLog.objects.bulk_create(tlog)
             
         
         groups=request.user.groups.values_list('name',flat = True)
         if groups[0] == "deputy range officer":
          application_detail.update(status = True,d=request.user,deputy_verify_text = request.data["summary"],current_app_status = "Range Officer Recommendation Pending After Filed Verification Completed" )
         else :
          application_detail.update(status = True,f_r=request.user ,deputy_verify_text = request.data["summary"] , current_app_status = "Range Officer Recommendation Pending After Filed Verification Completed") 
            
         return JsonResponse({'status': 'success', 'message': 'Successfully uploaded images and location details.'} , safe=False)
        except:
         return JsonResponse({'status': 'error', 'message': 'Something went wrong !'} , safe=False)          
        
def dep_upload_product_image_file(record_id, post_image, image_path, image_tag):
 image_name = ''
 image_path = settings.PROOF_OF_OWNERSHIP_PATH
 image_path = IMAGE_TAG[image_tag]
 if image_path=='form3':
  image_path = settings.FORM_THREE_FOREST_SIGN
 if not os.path.exists(image_path):
  os.makedirs(image_path)
  image_name = None
 if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
  try:
   filename = post_image['mime']
   filearr = filename.split('/')

   if len(filearr) > 1 :
    file_name = filearr[0]
    file_ext = filearr[1]
    image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
    imagefile = str(image_path)+str(image_name)
    imgstring = post_image["data"]
    imgstring1 = imgstring.split(',')
    imgdata = base64.b64decode(imgstring)
    with open(imagefile, 'wb+') as f:
        f.write(imgdata)
  except Exception as Error:
    print("----here",Error)
    pass

 return image_name



class new_application_form(APIView):
    permission_classes = [permissions.IsAuthenticated, ]
    @method_decorator(ratelimit(key='user_or_ip', rate='1/m', method='POST'))
    def post(self, request):
        validation_status = 'error'
        validation_message = 'Something went wrong!'
        name = request.data["name"]
        address = request.data["address"]
        survey_no = request.data["survey_no"]
        tree_proposed = request.data["tree_proposed"]
        village = request.data["village"]
        district = request.data["district"]
        block = request.data["block"]
        taluka = request.data["taluka"]
        division = request.data["division"]
        area_range = request.data["area_range"]
        pincode = request.data["pincode"]
        id_ty = request.data["id_type"]
        id_nu = request.data["id_number"]
        ownership_proof_img = request.data["ownership_proof_img"]
        revenue_approval_img = request.data["revenue_approval_img"]
        declaration_img = request.data["declaration_img"]
        aadhar_card_img = request.data["aadhar_card_img"]
        tree_species = request.data["tree_species"]
        purpose = request.data["purpose_cut"]
        log_details = request.data["log_details"]
        is_form = request.data["is_form_two"]
        if is_form == "1":
            is_form_tw = True
        else:
            is_form_tw = False
        rangedetails = Range.objects.get(name=area_range)
        
        revenue=RevenueOfficerdetail.objects.filter(range_name=rangedetails)
        print(revenue)
        for r in revenue:
         try:
          u = CustomUser.objects.get(id = r.Rev_user.id,is_delete= False)
          revenueid = u.id
         except:
             pass
        url = 'static/media/'
        application = Applicationform.objects.create(
            name=name, address=address, destination_state="",destination_details="",
            survey_no=survey_no, village=village, total_trees=tree_proposed,
            district=district,  pincode=pincode,id_card_number=id_nu,id_type=id_ty,
            purpose=purpose, block=block, taluka=taluka, division=division,
            area_range=area_range, by_user=request.user,assgn_deputy='assgned',species_of_trees=tree_species,is_form_two=is_form_tw
        )
        
        aadhar = user_upload_product_image_file(application.id, aadhar_card_img, url, 'AadharCard')
        revenue_approval = user_upload_product_image_file_rev_approval(application.id, revenue_approval_img, url, 'RevenueApproval')
        declaration = user_upload_product_image_file(application.id, declaration_img, url, 'Declaration')
        owership = user_upload_product_image_file(application.id, ownership_proof_img, url, 'ProofOfOwnership')
        
        
        application.proof_of_ownership_of_tree = owership

        image_doc = image_documents.objects.create(app_form=application,
                                                   revenue_approval=revenue_approval, declaration=declaration,
                                                    aadhar_detail=aadhar,
                                                   )
        application.verify_office = True
        application.application_status = 'P'
        application.reason_office = 'Recommended'
        application.approved_by_revenue_id = revenueid
        uid = request.user.id
        application.application_no = generate_app_id(uid, application.id)
        
        application.signature_img = True
        application.revenue_application = True
        application.location_sktech = True
        application.tree_ownership_detail = True
        application.aadhar_detail = True
        application.location_needed =True
        tlog = []
        application.trees_cutted = True
        
        if log_details != "":
            for i in log_details:
                print(i)
                timber = Timberlogdetails(appform=application, species_of_tree=i["species_of_tree"],
                                          length=i["length"], breadth=i["breadth"], volume=i["volume"])
                tlog.append(timber)
            Timberlogdetails.objects.bulk_create(tlog)
        if request.data["lat"] != "":
            if request.data["lon"] != "":
             application.location_lat = request.data["lat"]
             application.location_log = request.data["lon"]
             application.application_status = "P"
            else:
             application.application_status = "L"
        else:
            application.application_status = "L"  
        application.save()
        validation_status = 'success'
        validation_message = 'Data Saved Successfully.'
        
        return JsonResponse({'status': validation_status, 'application_id':application.id,'application_number':application.application_no}, safe=False)
def user_upload_product_image_file(record_id, post_image, image_path, image_tag):
 image_name = ''
 image_path = settings.PROOF_OF_OWNERSHIP_PATH
 image_path = IMAGE_TAG[image_tag]
 if image_path=='form3':
  image_path = settings.FORM_THREE_FOREST_SIGN
 if not os.path.exists(image_path):
  os.makedirs(image_path)
  image_name = None
 if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
  try:
   filename = post_image['mime']
   filearr = filename.split('/')

   if len(filearr) > 1 :
    file_name = filearr[0]
    file_ext = filearr[1]
    image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
    imagefile = str(image_path)+str(image_name)
    imgstring = post_image["data"]
    imgstring1 = imgstring.split(',')
    imgdata = base64.b64decode(imgstring)
    with open(imagefile, 'wb+') as f:
        f.write(imgdata)
  except Exception as Error:
    print("----here",Error)
    pass

 return image_name
def user_upload_product_image_file_rev_approval(record_id, post_image, image_path, image_tag):
 image_name = ''
 image_path = settings.REVENUE_APPROVAL_PATH
#  image_path = IMAGE_TAG[image_tag]
#  if image_path=='form3':
#   image_path = settings.FORM_THREE_FOREST_SIGN
 if not os.path.exists(image_path):
  os.makedirs(image_path)
  image_name = None
 if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
  try:
   filename = post_image['mime']
   filearr = filename.split('/')

   if len(filearr) > 1 :
    file_name = filearr[0]
    file_ext = filearr[1]
    image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
    imagefile = str(image_path)+str(image_name)
    imgstring = post_image["data"]
    imgstring1 = imgstring.split(',')
    imgdata = base64.b64decode(imgstring)
    with open(imagefile, 'wb+') as f:
        f.write(imgdata)
  except Exception as Error:
    print("----here",Error)
    pass

 return image_name



class get_app_details_new(APIView):
  permission_classes = [permissions.IsAuthenticated, ]
  def post(self, request):
    app = request.data['application_id']
    try:
     context = {}
     context['application_details']  = AppSerial(Applicationform.objects.get(id = int(app))).data
     return JsonResponse({'status': 'success', 'message': context}, safe=False)    
    except:
        return JsonResponse({'status': 'error', 'message': "Application not avaliable !"}, safe=False) 


class get_deputies(APIView):
  permission_classes = [permissions.IsAuthenticated, ]
  def post(self, request):
    range = request.data['range']
    # try:
    #  context = {}
    api = []
    data = ForestOfficerdetail.objects.filter(range_name_id=range) 
    for i in data:
     user = CustomUser.objects.get(id = i.fod_user_id)
     groups= user.groups.values_list('name',flat = True)
     if groups[0] == "deputy range officer":
      api.append({"id":user.id,"name":user.name})
    #  context['deputies']  = AppSerial(Applicationform.objects.get(id = int(app))).data
    print(api)
    return JsonResponse({'status': 'success', 'deputy range officers': api}, safe=False)    
    # except:
    #     return JsonResponse({'status': 'error', 'message': "Application not avaliable !"}, safe=False) 


class assgin_deputy(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
  groups=request.user.groups.values_list('name',flat = True)
  if groups[0] == "forest range officer":
    try:
     app_id=request.data['app_id']
     
     self = request.data['self']
     file = request.data['remark_file']
     text = request.data['remark_text']
     url = 'static/media/'
    
     application_detail = Applicationform.objects.get(id=app_id)
     if self == True:
         image = range1_upload_remark_image_file(application_detail.id, file, url, 'range_1_file')
         Applicationform.objects.filter(id=app_id).update(
  	assigned_deputy2_by=request.user,
  	assigned_deputy2_id = request.user,approved_by_r = "Yes",r=request.user,f_r = request.user,
  	assigned_deputy2_date=date.today(),range_1_file=image,range_1_text=text,current_app_status = "Deputy Range Officer Assigned for Field Verification"
    )
     else:    
      sel_deputy=request.data['deputy_id']
      image = range1_upload_remark_image_file(application_detail.id, file, url, 'range_1_file')
      Applicationform.objects.filter(id=app_id).update(
  	  assigned_deputy2_by=request.user,
  	   assigned_deputy2_id = sel_deputy,approved_by_r = "Yes",d=sel_deputy,r=request.user,range_1_file=image,range_1_text=text,
  	   assigned_deputy2_date=date.today(),current_app_status = "Deputy Range Officer Assigned for Field Verification"
       )
     return JsonResponse({'status': 'success', 'message':'Assigned Successfully'}, safe=False)
    except:
     return JsonResponse({'status': 'error', 'message':'Not Assigned !'}, safe=False)
  else:
    return JsonResponse({'status': 'error', 'message':'Access Denied !'}, safe=False)
  

  

class approve_cutting_pass_new(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
  groups=request.user.groups.values_list('name',flat = True)
  if groups[0] != "forest range officer":
    return JsonResponse({'status': 'error', 'message': "unauthorized api request"}, safe=False)
  try:
      if request.user.groups.values_list('name',flat = True)[0] == "forest range officer":
          pass 
      else:
          raise Exception("Error") 
      app = request.data['app_id']
      type = request.data['type']
      file = request.data['remark_file']
      text = request.data['remark_text']
      if type == "Approve":
       application = Applicationform.objects.filter(id = app)
       if application[0].status == False:
        return JsonResponse({'status': 'error', 'message': "Failed to approve Cutting Pass"}, safe=False)
       else:
        url = 'static/media/'
        image = range_upload_remark_image_file(application[0].id, file, url, 'range_2_file')
        logs = request.data['logs_selected']
        for log in logs:
         t = ApprovedTimberLog.objects.get(id=int(log))
         t.is_approved = True
         t.save()
        application.update(confirm_date = date.today(),application_status = "A",approved_by_r = "Yes",range_2_file=image,range_2_text=text, current_app_status = "Approved By Range Officer")
        return JsonResponse({'status': 'success', 'message': "Cutting Pass Approved"}, safe=False) 
      elif type == "Reject":
        application = Applicationform.objects.filter(id = app)
        url = 'static/media/'
        image = range_upload_remark_image_file(application[0].id, file, url, 'range_2_file')
        logs = request.data['logs_selected']
        for log in logs:
         t = ApprovedTimberLog.objects.get(id=int(log))
         t.is_approved = False
         t.save()
        application.update(confirm_date = date.today(),application_status = "R",approved_by_r = "No",range_2_file=image,range_2_text=text, current_app_status = "Rejected By Range Officer")
        return JsonResponse({'status': 'success', 'message': "Cutting Pass Rejected"}, safe=False) 
      else: 
          raise Exception("Error")    
  except:
      return JsonResponse({'status': 'error', 'message': "Failed to update Cutting Pass status"}, safe=False)
  
def range_upload_remark_image_file(record_id, post_image, image_path, image_tag):
 image_name = ''
 image_path = settings.RANGE_2_FILE
#  image_path = IMAGE_TAG[image_tag]

 if not os.path.exists(image_path):
  os.makedirs(image_path)
  image_name = None
 if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
  try:
   filename = post_image['mime']
   filearr = filename.split('/')

   if len(filearr) > 1 :
    file_name = filearr[0]
    file_ext = filearr[1]
    image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
    imagefile = str(image_path)+str(image_name)
    imgstring = post_image["data"]
    imgstring1 = imgstring.split(',')
    imgdata = base64.b64decode(imgstring)
    with open(imagefile, 'wb+') as f:
        f.write(imgdata)
  except Exception as Error:
    print("----here",Error)
    pass

 return image_name

def range1_upload_remark_image_file(record_id, post_image, image_path, image_tag):
 image_name = ''
 image_path = settings.RANGE_1_FILE
#  image_path = IMAGE_TAG[image_tag]

 if not os.path.exists(image_path):
  os.makedirs(image_path)
  image_name = None
 if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
  try:
   filename = post_image['mime']
   filearr = filename.split('/')

   if len(filearr) > 1 :
    file_name = filearr[0]
    file_ext = filearr[1]
    image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
    imagefile = str(image_path)+str(image_name)
    imgstring = post_image["data"]
    imgstring1 = imgstring.split(',')
    imgdata = base64.b64decode(imgstring)
    with open(imagefile, 'wb+') as f:
        f.write(imgdata)
  except Exception as Error:
    print("----here",Error)
    pass

 return image_name



class GetReq_log(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
    try:
     app = request.data['app_id']
     app = Applicationform.objects.get(id = app)
     logs = Timberlogdetails.objects.filter(appform=app)
     data = TimberSerializer(logs, many=True).data
     return JsonResponse({'status': 'success', 'data':data }, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 

class GetVerified_log(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
    try:
     app = request.data['app_id']
     app = Applicationform.objects.get(id = app)
     logs = ApprovedTimberLog.objects.filter(appform=app)
     data = ATimSerial(logs, many=True).data
     return JsonResponse({'status': 'success', 'data':data }, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 
 
class GetApproved_log(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
    try:
     app = request.data['app_id']
     app = Applicationform.objects.get(id = app)
     logs = ApprovedTimberLog.objects.filter(appform=app,is_approved= True)
     data = ATimSerial(logs, many=True).data
     return JsonResponse({'status': 'success', 'data':data }, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 
 
 
class GetPasses(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def get(self, request):
    try:
     application = Applicationform.objects.filter(by_user_id=request.user.id,is_noc=False).order_by('-id')
     tp = TransitPass.objects.filter(app_form__by_user_id=request.user.id).order_by('-app_form_id')
     app_data = AppSerial(application, many=True).data
     transit_data = Transits_serial(tp, many=True).data
     return JsonResponse({'status': 'success', 'applications':app_data, 'transits':transit_data }, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 
 
class GetCuttingPasses(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def get(self, request):
    try:
     application = Applicationform.objects.filter(by_user_id=request.user.id,is_noc=False).order_by('-id')
    #  tp = TransitPass.objects.filter(app_form__by_user_id=request.user.id).order_by('-app_form_id')
     app_data = AppSerial(application, many=True).data
    #  transit_data = Transits_serial(tp, many=True).data
     return JsonResponse({'status': 'success', 'applications':app_data }, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 

class GetTransitPasses(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def get(self, request):
    try:
    #  application = Applicationform.objects.filter(by_user_id=request.user.id,is_noc=False).order_by('-id')
     tp = TransitPass.objects.filter(app_form__by_user_id=request.user.id).order_by('-app_form_id')
    #  app_data = AppSerial(application, many=True).data
     transit_data = Transits_serial(tp, many=True).data
     return JsonResponse({'status': 'success',  'transits':transit_data }, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 
 
 
 
 
 
 
class GetOfficerTransitPasses(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def get(self, request):
  try:
   application = Applicationform.objects.all()
   groups=request.user.groups.values_list('name',flat = True)
   if groups[0] == "revenue officer":
    urange = RevenueOfficerdetail.objects.get(Rev_user = request.user.id)
   else:
    urange=ForestOfficerdetail.objects.get(fod_user_id=request.user.id)
   transit = []
   for i in application:
    if i.area_range == urange.range_name.name:
        ad = TransitPass.objects.filter(app_form=i,transit_status="Pending")
        if ad:
         data = Transits_serial(ad, many=True).data
         transit.append(data)
   merged_list = []
   for l in transit:
    merged_list += l  
   return JsonResponse({'status': 'success', 'transits':merged_list }, safe=False)
  except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 
 
 
class AddLocation(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
    try:
     app = request.data['app_id']
     application = Applicationform.objects.filter(id = app).update(location_lat = request.data['lat'],
                                                                    location_log =request.data['lon'],application_status="P")
     return JsonResponse({'status': 'success', 'applications':'Sucessfully updated location details.'}, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 

class GetTransitHistory(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
    try:
     app = request.data['app_id']
     application = Applicationform.objects.filter(id = app).update(location_lat = request.data['lat'],
                                                                    location_log =request.data['lon'],application_status="P")
     return JsonResponse({'status': 'success', 'applications':'Sucessfully updated location details.'}, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 
 
 
 
 
 
 
class CheckTransit(APIView):
  permission_classes = [permissions.IsAuthenticated, ]
  def post(self, request):
    try: 
     app = request.data['app_id']
     application = Applicationform.objects.get(id = app)
     data = AppSerial(application).data
     if application.application_status == "A":
      tim = ApprovedTimberLog.objects.filter(appform=application)
      t = []
      for ti in tim:
       a = ATimSerial(ti).data
       t.append(a)
      return JsonResponse({'status': 'success', 'app':data , "timber":t}, safe=False)
     else:
      return JsonResponse({'status': 'error', 'message': "Application not approved"}, safe=False) 
    except:
        return JsonResponse({'status': 'error', 'message': "Application not avaliable"}, safe=False) 

class apply_orign_transit(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
  try:
   app_id = request.data['app_id']
   app = Applicationform.objects.get(id=app_id)
   date1 = date.today()
   transit_old = TransitPass.objects.filter(app_form=app)
   print(transit_old)
   transit = TransitPass()
   transit.save()
   transit = TransitPass(id=transit.id)
   x = app.application_no.replace("/", "-")
   transit.transit_number = 'TP-'+str(x) +str(transit.id)
   transit.app_form = app
   if app.application_status == "A":
    transit.transit_status = "Pending"
    transit.destination_details = request.data['destination_details']
    transit.destination_district = request.data['dest_state']
    logs = request.data['logs_selected']
    
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
        admit.swan_length = log['swan_length']
        admit.swan_breadth = log['swan_breadth']
        admit.swan_height = log['swan_height']
        
     admit.is_transit_applied = True
     admit.save()
    transit.save()
    return JsonResponse({'status': 'success', 'message': "Transit Applied"}, safe=False) 
  except:
      return JsonResponse({'status': 'error', 'message': "Failed to apply Transit Pass"}, safe=False)
  
class SeeTransit(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
  try:
   pk = request.data['transit_number']
   context = {}
   transit_data = TransitPass.objects.get(transit_number=pk)
   context['transit'] = Transits_serial( transit_data ).data
   app_data = Applicationform.objects.get(id = transit_data.app_form.id)
   context['application'] = AppSerial(app_data).data
   cuurent_request = ProductTransit.objects.filter(transit_pass = transit_data)
   names = []
   for each in cuurent_request:
      
       names.append(each.approved_timber.species_of_tree)
   previous_transits = ProductTransit.objects.filter(app= transit_data.app_form.id)
   context['curent_request'] = Produsct_ch_serial(cuurent_request, many=True).data
   context['previous_transits'] = Produsct_ch_serial(previous_transits, many=True).data
   images = image_documents.objects.get(app_form= transit_data.app_form)
   context['image_documents'] = ImageSerial(images).data
   for each,n in zip(context['curent_request'],names):
       each['name'] = n
   return JsonResponse({'status': 'success', 
                       'transit': context['transit'] ,
                       'application': context['application'] ,
                       'curent_request': context['curent_request'] ,
                       'previous_transits': context['previous_transits'],
                    #    'image_documents': context['image_documents'],
                       }, safe=False)
  except:
      return JsonResponse({'status': 'error', 'message': "Failed to apply Transit Pass"}, safe=False)


class ApproveNewProductTransit(APIView):
 permission_classes = [permissions.IsAuthenticated, ]
 def post(self, request):
  groups=request.user.groups.values_list('name',flat = True)
  if groups[0] != "forest range officer":
    return JsonResponse({'status': 'error', 'message': "unauthorized api request"}, safe=False)
  pk = request.data['transit_number']
  transit = TransitPass.objects.get(transit_number=pk)
  app = Applicationform.objects.get(id = transit.app_form.id)
  try:
   file = request.data['remark_file']
   url = 'media/upload/transit_remark/'
   img = upload_remark_transit_image_file(transit.transit_number,file,url,"transit_remark")
   transit.remarks_img = img
  except:
    transit.remarks_img = ""
  if request.data['action']=="Approve":   
   if app.application_status == "A":
    transit.remarks = request.data['remark_text']
    transit.transit_status = "Approved" 
    all_logs =  ProductTransit.objects.filter(transit_pass = transit).update(is_transit_approved = 2)    
    logs = request.data['logs_to_approve']
    for log in logs:
     t = ProductTransit.objects.get(id = int(log))
     t.is_transit_approved = 1
     t.save()  
    qr_code = get_qr_code(pk)
    transit.qr_code=qr_code
    transit.qr_code_img=generate_qrcode_image(qr_code, settings.QRCODE_PATH, pk)
    transit.save()
    message = "Transit Pass Approved"
  else:
    transit.transit_status = "Rejected" 
    transit.remarks = request.data['remark_text']
    all_logs =  ProductTransit.objects.filter(transit_pass = transit).update(is_transit_approved = 2)
    transit.save()
    message ="Transit Pass Rejected"
  return JsonResponse({'status': 'success', 'message': message}, safe=False)

def upload_remark_transit_image_file(record_id, post_image, image_path, image_tag):
 image_name = ''
 image_path = settings.TRANSIT_FILE
 if not os.path.exists(image_path):
   os.makedirs(image_path)
 image_name = None
 if post_image != '' and image_path != '' and image_tag != '' and record_id !='':
  try:
   filename = post_image['mime']
   filearr = filename.split('/')
   if len(filearr) > 1 :
    file_name = filearr[0]
    file_ext = filearr[1]
    image_name =image_tag+"_"+str(record_id)+"_image."+str(file_ext)
    imagefile = str(image_path)+str(image_name)
    imgstring = post_image["data"]
    imgstring1 = imgstring.split(',')
    imgdata = base64.b64decode(imgstring)
    with open(imagefile, 'wb+') as f:
        f.write(imgdata)
  except Exception as Error:
    print("----here",Error)
    pass

 return image_name

class newsendotp(APIView):
 permission_classes = [permissions.AllowAny,]
 def post(self, request):
    try:
        
     mobile = request.data['mobile']
     otp = new_otp_generateOTP()
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
        return JsonResponse({'status': 'success', 'applications':'Exceded daily limit'}, safe=False)
     new_sendSingleSMS(USERNAME, PASSWORD, SENDERID, message, mobile, templateid, key)
     return JsonResponse({'status': 'success', 'applications':'Sucessfully sent OTP.'}, safe=False)
    except:
     return JsonResponse({'status': 'error', 'app':'Something went wrong!'}, safe=False) 

def new_sendSingleSMS(username, encryp_password, senderid, message, mobileno,templateid, deptSecureKey):
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
  

def new_otp_generateOTP() :
    digits = "0123456789"
    OTP = ""
    for i in range(6) :
        OTP += digits[math.floor(random.random() * 10)]

    return OTP

# from django.http import FileResponse
# class GetXAccelFiles(APIView):
#  permission_classes = [permissions.AllowAny, ]
#  def get(self, request):
#   imgs = ['media\\upload\\aadhar_card\\AadharCard_137332_image.png','media\\upload\\declaration\\Declaration_137332_image.png']
#   for i in imgs:
#    img = open(r''+i, 'rb')
#    response = FileResponse(img)
#    return response

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
 