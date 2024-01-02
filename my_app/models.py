from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _
from django.core.validators import RegexValidator
from .managers import CustomUserManager
from datetime import datetime, date
from django.conf import settings
from django.contrib.auth.models import Group

Group.add_to_class('is_delete', models.BooleanField(default=False))
# Create your models here.
STATUS_CHOICES = (
    ('S', _("Submitted")),
    ('C', _("Recheck")),
    ('L', _("Location Pending")),
    ('P', _("Pending")),
    ('A', _("Approved")),
    ('R', _("Rejected")),
)




class CustomUser(AbstractUser):
    username = None
    user_id = models.CharField(max_length=30, blank=True, null=True)
    phone = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=50, blank=True, null=True)
    email = models.CharField(max_length=50, blank=True, null=True, unique=True)
    signup_date = models.DateTimeField(auto_now_add=True)
    login_date = models.DateTimeField(auto_now_add=True)
    login_status = models.CharField(max_length=255, default='')
    profile_pic = models.CharField(max_length=255, default='')
    user_status = models.CharField(max_length=255, default='')
    address = models.CharField(max_length=255, default='')
    photo_proof_img = models.CharField(max_length=255, default='no_image.png')
    photo_proof_no = models.CharField(max_length=255, blank=True, null=True)
    photo_proof_name = models.CharField(max_length=255, blank=True, null=True)
    photo_proof_type = models.ForeignKey('PhotoProof', on_delete=models.CASCADE, blank=True, null=True,
                                         related_name='custom_user_photo_proof')
    aadhar_detail = models.CharField(max_length=25, default='')
    is_delete = models.BooleanField(default=False)
    firmstatus = models.BooleanField(default=False)
    usr_category = models.CharField(max_length=255, default='no_data')
    mobile_otp = models.CharField(max_length=20, default='no_data')
    email_code = models.CharField(max_length=20, default='no_data')
    mobile_otp = models.CharField(max_length=20, default='no_data')
    mobile_verified = models.CharField(max_length=20, default='False')
    email_verified = models.CharField(max_length=20, default='False')
    forgot_code = models.CharField(max_length=20, default='no_data')
    no_of_attempts_forgot = models.CharField(max_length=20, default='0')
    no_of_attempts_register = models.CharField(max_length=20, default='0')
    mobile_otp_created_time = models.CharField(max_length=100, default='')
    forgot_otp_created_at = models.CharField(max_length=100,default='')
    email_otp_created_time = models.CharField(max_length=100, default='')
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __unicode__(self):
        return self.id


class FirmUser(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    organization = models.CharField(max_length=255, default='')
    pan_card = models.CharField(max_length=255, default='')
    gst = models.CharField(max_length=255, default='')
    cin_number = models.CharField(max_length=255, default='')
    tan_number = models.CharField(max_length=255, default='')
    service_tax = models.CharField(max_length=255, default='')
    website = models.CharField(max_length=255, null=True, default='')

class PhotoProof(models.Model):
    name = models.CharField(max_length=200, blank=True, null=True)
    is_delete = models.BooleanField(default=False)
    created_date = models.DateField(auto_now_add=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='photo_proof_user')

    def __unicode__(self):
        return self.id


class TreeSpecies(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True)
    is_delete = models.BooleanField(default=False)
    created_date = models.DateField(auto_now_add=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='tree_species_user')
    is_noc = models.BooleanField(default=False)

    def __unicode__(self):
        return self.id

class AllSpecies(models.Model):
    serial = models.IntegerField(default=0)
    name = models.CharField(max_length=255,blank=True,null=True)
    scientific_name = models.CharField(max_length=225,blank=True,null=True)
    division = models.CharField(max_length=225,blank=True,null=True)
    
    def __str__(self):
        return self.name

class State(models.Model):
    name = models.CharField(max_length=225, blank=True, null=True)
    created_date = models.DateField(auto_now_add=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='state_created_by')
    is_delete = models.BooleanField(default=False)


class Division(models.Model):
    name = models.CharField(max_length=225, blank=True, null=True)
    state = models.ForeignKey(State, on_delete=models.CASCADE, blank=True, null=True, related_name='division_state')
    created_date = models.DateField(auto_now_add=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='division_created_by')
    is_delete = models.BooleanField(default=False)


class Range(models.Model):
    name = models.CharField(max_length=225, blank=True, null=True)
    created_date = models.DateField(auto_now_add=True)
    division = models.ForeignKey(Division, on_delete=models.CASCADE, blank=True, null=True,
                                 related_name='range_division')
    created = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='range_created_by')
    is_delete = models.BooleanField(default=False)
    


class CheckPost(models.Model):
    circle = models.CharField(max_length=500, blank=True, null=True)
    division = models.CharField(max_length=500, blank=True, null=True)
    range = models.CharField(max_length=500, blank=True, null=True)
    checkpost = models.CharField(max_length=200, blank=True, null=True)
    
class CheckPostsKerala(models.Model):
    id = models.AutoField(primary_key=True)
    circle = models.CharField(max_length=500)
    division = models.CharField(max_length=500)
    range = models.CharField(max_length=500)
    name = models.CharField(max_length=500)
    
    def __str__(self):
        return self.name

class DivisionOfficerdetail(models.Model):
    div_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                 related_name='dod_div_user')
    post = models.CharField(max_length=200, blank=True, null=True)
    office_address = models.CharField(max_length=500, blank=True, null=True)
    division_name = models.ForeignKey(Division, on_delete=models.CASCADE, blank=True, null=True, related_name='dod_div')


class StateOfficerdetail(models.Model):
    state_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='sod_state_user')
    post = models.CharField(max_length=200, blank=True, null=True)
    office_address = models.CharField(max_length=500, blank=True, null=True)
    state_name = models.CharField(max_length=200, blank=True, null=True)


class ForestOfficerdetail(models.Model):
    fod_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True, related_name='fod_user')
    post = models.CharField(max_length=200, blank=True, null=True)
    office_address = models.CharField(max_length=500, blank=True, null=True)
    range_name = models.ForeignKey(Range, on_delete=models.CASCADE, blank=True, null=True, related_name='fod_range')
    division_name = models.ForeignKey(Division, on_delete=models.CASCADE, blank=True, null=True, related_name='fod_div')


class CheckPostOfficerdetail(models.Model):
    id = models.AutoField(primary_key=True)
    check_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='check_user')
    post = models.CharField(max_length=200, blank=True, null=True)
    office_address = models.CharField(max_length=500, blank=True, null=True)
    checkpost = models.ForeignKey(CheckPostsKerala, on_delete=models.CASCADE)
    
    


class RevenueOfficerdetail(models.Model):
    Rev_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True, related_name='rev_user')
    post = models.CharField(max_length=200, blank=True, null=True)
    office_address = models.CharField(max_length=500, blank=True, null=True)
    range_name = models.ForeignKey(Range, on_delete=models.CASCADE, blank=True, null=True, related_name='rev_range')
    division_name = models.ForeignKey(Division, on_delete=models.CASCADE, blank=True, null=True, related_name='rev_div')


class SendOtp(models.Model):
    otp_owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True, related_name='user',
                                  related_query_name='user')
    otp = models.CharField(max_length=20, blank=True, null=True)
    otp_verified = models.BooleanField(default=False)

    def _unicode_(self):
        return self.id


class Applicationform(models.Model):
    application_no = models.CharField(max_length=100, blank=True, null=True ,default='')
    by_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                related_name='applicationform_by_user')
    name = models.CharField(max_length=100, blank=True, null=True ,default='')
    address = models.CharField(max_length=500, blank=True, null=True,default='')
    id_type = models.CharField(max_length=100, blank=True, null=True,default='')
    id_card_number = models.CharField(max_length=100, blank=True, null=True,default='')
    survey_no = models.CharField(max_length=50, blank=True, null=True,default='')
    state = models.CharField(max_length=255, blank=True, default='')
    other_state = models.BooleanField(default=False)
    district = models.CharField(max_length=255, blank=True,default='')
    taluka = models.CharField(max_length=255, blank=True,default='')
    block = models.CharField(max_length=255, default='')
    division = models.CharField(max_length=255, blank=True,default='')
    area_range = models.CharField(max_length=255, blank=True,default='')
    pincode = models.CharField(max_length=15, blank=True,default='')
    approved_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                    related_name='applicationform_approved_by')
    proof_of_ownership_of_tree = models.CharField(max_length=255, blank=True, default='')
    village = models.CharField(max_length=255, default='')
    species_of_trees = models.CharField(max_length=255, default='')
    location_lat = models.CharField(max_length=150,default='')
    location_log = models.CharField(max_length=150,default='')
    purpose = models.CharField(max_length=255, default='')
    trees_proposed_to_cut = models.CharField(max_length=255, default='')
    trees_cutted = models.BooleanField(default=False)
    total_trees = models.CharField(max_length=255, default='')
    destination_details = models.CharField(max_length=500, null=True ,default="")
    destination_state = models.CharField(max_length=500, null=True,default='')
    signature_img = models.BooleanField(default=False)
    revenue_application = models.BooleanField(default=False)
    location_sktech = models.BooleanField(default=False)
    tree_ownership_detail = models.BooleanField(default=False)
    aadhar_detail = models.BooleanField(default=False)
    application_status = models.CharField(choices=STATUS_CHOICES, default='P', max_length=3)
    disapproved_reason = models.FileField(upload_to='static/reasons/', null=True,default='')
    verify_office = models.BooleanField(default=False)
    reason_office = models.FileField(upload_to='static/reasons/', default='')
    verify_office_date = models.DateField(auto_now=True, null=True)
    depty_range_officer = models.BooleanField(default=False)
    reason_depty_ranger_office = models.FileField(upload_to='static/reasons/', default='')
    deputy_officer_date = models.DateField(blank=True, null=True)
    verify_range_officer = models.BooleanField(default=False)
    reason_range_officer = models.FileField(upload_to='static/reasons/', default='')
    range_officer_date = models.DateField(blank=True, null=True)
    division_officer = models.BooleanField(default=False)
    reason_division_officer = models.FileField(upload_to='static/reasons/', default='')
    division_officer_date = models.DateField(blank=True, null=True)
    payment = models.CharField(max_length=100, default='')
    created_date = models.DateField(auto_now_add=True)
    appsecond_one_date = models.DateField(blank=True, null=True)
    appsecond_two_date = models.DateField(blank=True, null=True)
    deputy2_date = models.DateField(blank=True, null=True)
    transit_pass_created_date = models.DateField(default='2021-03-19', blank=True, null=True)
    transit_pass_id = models.IntegerField(default=0)
    tp_expiry_status = models.BooleanField(default=False)
    tp_expiry_date = models.DateField(default='2021-03-19')
    verify_deputy2 = models.BooleanField(default=False)
    reason_deputy2 = models.FileField(upload_to='static/reasons/', default='')
    deputy2_date = models.DateField(blank=True, null=True)
    approved_by_deputy2 = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                            related_name='applicationform_approved_by_deputy2')
    approved_by_deputy = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                           related_name='applicationform_approved_by_deputy')
    approved_by_revenue = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                            related_name='applicationform_approved_by_revenue')
    approved_by_division = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                             related_name='applicationform_approved_by_division')
    disapproved_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                       related_name='applicationform_disapproved_by')
    disapproved_by_grp = models.CharField(max_length=50, default='')
    log_updated_by_user = models.BooleanField(default=False)
    is_noc = models.BooleanField(default=False)
    is_form_two = models.BooleanField(default=False)
    deemed_approval = models.BooleanField(default=False)
    deemed_approval_1 = models.BooleanField(default=False)
    assigned_deputy1 = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                         related_name='applicationform_assigned_deputy1')
    assigned_deputy1_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                            related_name='applicationform_assigned_deputy1_by')
    assigned_deputy1_date = models.DateField(blank=True, null=True)
    assigned_deputy2 = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                         related_name='applicationform_assigned_deputy2')
    assigned_deputy2_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                            related_name='applicationform_assigned_deputy2_by')
    assigned_deputy2_date = models.DateField(blank=True, null=True)
    marks_form3 = models.CharField(max_length=500, default='')
    whence_form3 = models.CharField(max_length=500, default='')
    destination_form3 = models.CharField(max_length=500, default='')
    route_form3 = models.CharField(max_length=500, default='')
    time_allowed_form3 = models.CharField(max_length=500, default='')
    remarks_form3 = models.CharField(max_length=500, default='')
    is_form3 = models.BooleanField(default=False)
    form3_created_date = models.DateField(blank=True, null=True)
    form3_created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                         related_name='applicationform_form3_created_by')
    form3_signature = models.CharField(max_length=255, default='no_image.png')
    verify_forest1 = models.BooleanField(default=False)
    reason_forest1 = models.FileField(upload_to='static/reasons/', default='')
    forest1_date = models.DateField(blank=True, null=True)
    approved_by_forest1 = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                            related_name='applicationform_approved_by_forest1')
    assgn_deputy = models.CharField(max_length=500, default='')
    d = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, related_name='slected_deputy')
    r = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, related_name='slected_range')
    approved_by_r = models.CharField(max_length=10,default="No")
    location_needed = models.BooleanField(default=True)
    status = models.BooleanField(default=False)
    f_r = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, related_name='field_range')
    range_1_text = models.TextField()
    range_1_file = models.CharField(max_length=200, default='no_image.png')
    range_2_text = models.TextField()
    range_2_file = models.CharField(max_length=200, default='no_image.png')
    deputy_verify_text = models.TextField()
    deputy_verify_file = models.CharField(max_length=200, default='no_image.png')
    recheck_remark =models.TextField()
    recheck_image = models.CharField(max_length=200, default='no_image.png')
    current_app_status = models.TextField(default='Range Officer Recommendation Pending For Field Verification')
    confirm_date = models.DateField(blank=True, null=True)
    def __unicode__(self):
        return self.id



class Species_geodetails(models.Model):
    appform = models.ForeignKey(Applicationform, on_delete=models.CASCADE, blank=True, null=True,
                                related_name='species_detaila_app_id')
    species_tree = models.ForeignKey(TreeSpecies, on_delete=models.CASCADE, blank=True, null=True,
                                     related_name='species_geodetails_species_name')
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    length = models.FloatField(blank=True, null=True)
    breadth = models.FloatField(blank=True, null=True)
    volume = models.FloatField(blank=True, null=True)

    def __unicode__(self):
        return self.id





class image_documents(models.Model):
    app_form = models.ForeignKey(Applicationform, on_delete=models.CASCADE, blank=True, null=True,
                                 related_name='app_image')

    signature_img = models.CharField(max_length=200, default='no_image.png')
    revenue_approval = models.CharField(max_length=200, default='no_image.png')
    declaration = models.CharField(max_length=200, default='no_image.png')
    revenue_application = models.CharField(max_length=200, default='no_image.png',null=True)
    location_sktech = models.CharField(max_length=200, default='no_image.png',null=True)
    tree_ownership_detail = models.CharField(max_length=200, default='no_image.png',null=True)
    aadhar_detail = models.CharField(max_length=200, default='no_image.png')
    location_img1 = models.CharField(max_length=200, default='no_image.png')
    location_img2 = models.CharField(max_length=200, default='no_image.png')
    location_img3 = models.CharField(max_length=200, default='no_image.png')
    location_img4 = models.CharField(max_length=200, default='no_image.png')
    image1_lat = models.CharField(max_length=200, default='no lat')
    image2_lat = models.CharField(max_length=200, default='no lat')
    image3_lat = models.CharField(max_length=200, default='no lat')
    image4_lat = models.CharField(max_length=200, default='no lat')
    image1_log = models.CharField(max_length=200, default='no log')
    image2_log = models.CharField(max_length=200, default='no log')
    image3_log = models.CharField(max_length=200, default='no log')
    image4_log = models.CharField(max_length=200, default='no log')

    def __unicode__(self):
        return self.id




class RoleMethod(models.Model):
    parent = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True,
                               related_name='rolemethod_parent')
    method_name = models.CharField(blank=True, max_length=250, null=True)
    name = models.CharField(blank=True, max_length=150)
    types = models.CharField(blank=True, max_length=150, default=True)
    is_delete = models.BooleanField(default=True)
    active = models.BooleanField(default=False)


class RolePermission(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True, null=True, related_name='role_group')
    method = models.ForeignKey(RoleMethod, on_delete=models.CASCADE)
    created_date = models.DateField(auto_now_add=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='role_created_by')


class District(models.Model):
    district_name = models.CharField(max_length=200, default='')

    def __unicode__(self):
        return self.id



class Taluka(models.Model):
    dist = models.ForeignKey(District, on_delete=models.CASCADE, blank=True, null=True, related_name='District')
    taluka_name = models.CharField(max_length=200, default='')

    def __unicode__(self):
        return self.id


class Village(models.Model):
    taluka = models.ForeignKey(Taluka, on_delete=models.CASCADE, blank=True, null=True, related_name='Taluka')
    village_name = models.CharField(max_length=200, default='')
    is_notified = models.BooleanField(default=False)

    def __unicode__(self):
        return self.id

class TempLinkage(models.Model):
    id = models.BigAutoField(primary_key=True)
    village = models.CharField(max_length=255, blank=True, null=True)
    range = models.CharField(max_length=255, blank=True, null=True)
    division = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'temp_linkage'

# class NotifiedVillages(models.Model):
#     taluka = models.ForeignKey(Taluka, on_delete=models.CASCADE, blank=True, null=True, related_name='Taluka')
#     village_name = models.CharField(max_length=200, default='')
#     is_notified = models.BooleanField()

class ScanedDetails_View(models.Model):
    checkpost_officer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    app_form = models.ForeignKey(Applicationform, on_delete=models.CASCADE, blank=True, null=True)
    checkpost = models.ForeignKey(CheckPostsKerala, on_delete=models.CASCADE, blank=True, null=True)
    check_log = models.CharField(max_length=50, default='no log')
    check_lat = models.CharField(max_length=50, default='no lat')
    scan_date = models.DateTimeField(auto_now_add=True)
    remark = models.CharField(max_length=50, default='')
    user_group = models.CharField(max_length=50, default='')


class Buyer_Seller(models.Model):
    by_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    sel_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="sel_user", blank=True, null=True)
    selected = models.BooleanField(default=False)
    name = models.CharField(max_length=50, default='')
    phone = models.CharField(max_length=50, default='')
    address = models.CharField(max_length=50, default='')
    timber_name = models.CharField(max_length=50, default='')
    timber_image = models.FileField(default='no_image.png')
    pincode = models.CharField(max_length=255, default='')
    date = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=100, default="active")
    timber_url = models.CharField(max_length=50, default='')
    quantity = models.CharField(max_length=50, default='')
    division = models.CharField(max_length=50, default='')
    dist = models.CharField(max_length=50, default='')

class Buyer_Requirement(models.Model):
    by_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
    name = models.CharField(max_length=50, default='')
    phone = models.CharField(max_length=50, default='')
    address = models.CharField(max_length=50, default='')
    timber_name = models.CharField(max_length=50, default='')
    date = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=100, default="active")
    timber_url = models.CharField(max_length=50, default='')
    quantity = models.CharField(max_length=50, default='')
    division = models.CharField(max_length=50, default='')
    dist = models.CharField(max_length=50, default='')




class Route_checks(models.Model):
    check_post = models.ForeignKey(CheckPostsKerala, on_delete=models.CASCADE) 
    application = models.ForeignKey(Applicationform, on_delete=models.CASCADE)
    is_passed = models.BooleanField(default=False)
    def __str__(self):
        return self.check_post

class TransitPass(models.Model):
    id = models.AutoField(primary_key=True)
    transit_number = models.CharField(max_length=200, blank=True)
    app_form = models.ForeignKey(Applicationform, on_delete=models.CASCADE, blank=True, null=True,
                                 related_name='transitpass_app')
    destination_details = models.CharField(max_length=500, null=True )
    destination_district = models.CharField(max_length=500, null=True)
    transit_status = models.CharField(max_length=500, default='None')
    transit_req_date = models.DateField( auto_now=True)
    qr_code = models.CharField(max_length=200, blank=True, null=True)
    qr_code_img = models.CharField(max_length=200, blank=True, null=True)
    vehicle_reg_no = models.CharField(max_length=100, blank=True, null=True)
    driver_name = models.CharField(max_length=200, blank=True, null=True)
    driver_phone = models.CharField(max_length=20, blank=True, null=True)
    mode_of_transport = models.CharField(max_length=200, blank=True, null=True)
    license_image = models.CharField(max_length=200, blank=True, null=True)
    photo_of_vehicle_with_number = models.CharField(max_length=200, blank=True, null=True)
    verification_status = models.BooleanField(default=False)
    state = models.CharField(max_length=255, blank=True, default='')
    district = models.CharField(max_length=255, blank=True)
    taluka = models.CharField(max_length=255, blank=True)
    block = models.CharField(max_length=255, blank=True)
    village = models.CharField(max_length=255, blank=True)
    created_date = models.DateField(auto_now=True)
    qr_url = models.CharField(max_length=200, blank=True, null=True)
    remarks = models.TextField()
    remarks_img = models.CharField(max_length=200, blank=True, null=True)
    def __unicode__(self):
        return self.id    

class Vehicle_detials(models.Model):
    app_form = models.ForeignKey(Applicationform, on_delete=models.CASCADE, blank=True, null=True,
                                 related_name='app_vehicle')
    transit = models.ForeignKey(TransitPass,on_delete=models.CASCADE,null=True)
    vehicle_reg_no = models.CharField(max_length=100, blank=True, null=True)
    driver_name = models.CharField(max_length=200, blank=True, null=True)
    driver_phone = models.CharField(max_length=20, blank=True, null=True)
    mode_of_transport = models.CharField(max_length=200, blank=True, null=True)
    license_image = models.CharField(max_length=200, blank=True, null=True)
    photo_of_vehicle_with_number = models.CharField(max_length=200, blank=True, null=True)

    def __unicode__(self):
        return self.id
    
class Timberlogdetails(models.Model):
    appform = models.ForeignKey(Applicationform, on_delete=models.CASCADE, blank=True, null=True, related_name='app_id')
    transit = models.ForeignKey(TransitPass,on_delete=models.CASCADE,blank=True,null=True)
    species_of_tree = models.CharField(max_length=100, blank=True, null=True)
    length = models.FloatField(blank=True, null=True)
    breadth = models.FloatField(blank=True, null=True)
    volume = models.FloatField(blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    log_qr_code = models.CharField(max_length=200, blank=True, null=True)
    log_qr_code_img = models.CharField(max_length=200, blank=True, null=True)
    is_transited = models.BooleanField(default=False)
    def __unicode__(self):
        return self.id
class ApprovedTimberLog(models.Model):
    appform = models.ForeignKey(Applicationform, on_delete=models.CASCADE)
    transit = models.ForeignKey(TransitPass,on_delete=models.CASCADE,blank=True,null=True)
    species_of_tree = models.CharField(max_length=100, blank=True, null=True)
    length = models.FloatField(blank=True, null=True)
    breadth = models.FloatField(blank=True, null=True)
    volume = models.FloatField(blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    log_qr_code = models.CharField(max_length=200, blank=True, null=True)
    log_qr_code_img = models.CharField(max_length=200, blank=True, null=True)
    is_applied = models.BooleanField(default=False)
    is_transit = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=False)
    qr_data = models.TextField(blank=True, null=True)
    def __unicode__(self):
        return self.id



class CheckPostPassTransit(models.Model):
    app = models.ForeignKey(Applicationform,on_delete=models.CASCADE)
    transit = models.ForeignKey(TransitPass,on_delete=models.CASCADE)
    checkpost = models.ForeignKey(CheckPostsKerala,on_delete=models.CASCADE)
    checkofficer = models.ForeignKey(CheckPostOfficerdetail, on_delete=models.CASCADE,null=True,blank=True)
    check_lat = models.CharField(max_length=200,default='')
    check_lon = models.CharField(max_length=200,default='') 
    is_passed = models.BooleanField(default=False)   


class ProductTransit(models.Model):
    app = models.ForeignKey(Applicationform,on_delete=models.CASCADE)
    approved_timber = models.ForeignKey(ApprovedTimberLog,on_delete=models.CASCADE)
    transit_pass = models.ForeignKey(TransitPass,on_delete=models.CASCADE,blank=True,null=True)
    product = models.CharField(max_length=100)
    log_height = models.CharField(max_length=100)
    log_mdh = models.CharField(max_length=100)
    firewood_weight = models.CharField(max_length=100)
    swan_length = models.CharField(max_length=100)
    swan_breadth = models.CharField(max_length=100)
    swan_height = models.CharField(max_length=100)
    is_transit_applied = models.BooleanField(default=False)
    is_transit_approved = models.IntegerField(default=0)
    product_qr_code = models.CharField(max_length=200, blank=True, null=True)
    product_qr_code_img = models.CharField(max_length=200, blank=True, null=True)
    qr_data = models.TextField(blank=True, null=True)
    applied_date = models.DateTimeField(auto_now_add=True)


class LoginAttempts(models.Model):
    ip = models.CharField(max_length=200,null=True)
    attempts = models.IntegerField(null=True)
    last_tried = models.DateTimeField(auto_now=True,null=True)
    
class OtpAttemps(models.Model):
    phone = models.CharField(max_length=20)
    otp_count = models.IntegerField(null=True, blank=True, default=0)
    last_otp_date = models.CharField(max_length=100 ,null=True, blank=True, default="")