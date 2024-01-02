from knox.views import LogoutView
from django.urls import path,include
from .views import *
from rest_framework import routers
from rest_apis import views
# LoginAPI

urlpatterns = [
path('auth/', include('knox.urls')),
path('auth/LoginAPI',LoginAPI.as_view()),
path('auth/NewLogin',NewLogin.as_view()),
path('auth/NewRegisterAPI',NewRegisterAPI.as_view()),
path('auth/RegisterAPI',RegisterAPI.as_view()),
path('auth/OtpVerify',OtpVerify.as_view()),
path('auth/forgotpassword',ForgotPassword.as_view()),
path('auth/forgotverifyotp',ForgotOtpVerify.as_view()),
path('auth/changepassword',ChangeForgotPasswordView.as_view()),
path('auth/InsertRecord',NewInsertRecord.as_view()),

path('auth/Formtwophaseone',Formtwophaseone.as_view()),
path('auth/PhaseTwoFormtwo',PhaseTwoFormtwo.as_view()),

path('auth/new_approve_transit_pass',new_approve_transit_pass.as_view()),
path('auth/FormTwoAssignDeputy',FormTwoAssignDeputy.as_view()),
path('auth/FormThree',FormThree.as_view()),



path('auth/TreeSpeciesList',TreeSpeciesList.as_view()),


path('auth/NewInsertRecord',NewInsertRecord.as_view()),
path('auth/ListViewApplication',ListViewApplication.as_view()),
path('auth/EditProfile', EditProfile.as_view()),
path('auth/ViewProfile', ViewProfile.as_view()),
# 
path('auth/new_transit_pass_pdf/<int:applicant_no>/', new_transit_pass_pdf,name='new_transit_pass_pdf'),
path('auth/new_user_report/<int:applicant_no>/', new_user_report,name='new_user_report'),
path('auth/qr_code_pdf/<int:applicant_no>/', qr_code_pdf,name='qr_code_pdf'),
path('auth/summary_report/', summary_report,name='summary_report'),

path('auth/ApprovedListViewApplication',ApprovedListViewApplication.as_view()),
path('auth/DfoApprovedListViewApplication',DfoApprovedListViewApplication.as_view()),
path('auth/sfdApprovedListViewApplication',sfdApprovedListViewApplication.as_view()),


path('auth/PendingListViewApplication',PendingListViewApplication.as_view()),
path('auth/ListAddImageApplication',ListAddImageApplication.as_view()),
path('auth/DfoPendingListViewApplication',DfoPendingListViewApplication.as_view()),
path('auth/sfdPendingListViewApplication',sfdPendingListViewApplication.as_view()),



path('auth/approve_transit_pass', approve_transit_pass.as_view(),name='approve_transit_pass'),

path('auth/UpdateVehicle',UpdateVehicle.as_view()),
path('auth/UpdateTimberlog',UpdateTimberlog.as_view(),name='UpdateTimberlog'),

path('auth/UpdateVehicle2/<int:app_id>/',UpdateVehicle2.as_view(),name='UpdateVehicle2'),


path('auth/ViewApplication',ViewApplication.as_view()),

path('auth/ListRange',ListRange.as_view()),
path('auth/LoadDivision',LoadDivision.as_view()),
path('auth/ListDistrict',ListDistrict.as_view()),
path('auth/LoadTaluka',LoadTaluka.as_view()),
path('auth/LoadVillage',LoadVillage.as_view()),
path('auth/dashbord_chart',dashbord_chart.as_view()),

path('auth/dashbord_AppList',dashbord_AppList.as_view()),

path('auth/need_field_verification',need_field_verification.as_view()),
path('auth/success_field_verification',success_field_verification.as_view()),
path('auth/failed_field_verification',failed_field_verification.as_view()),
path('auth/Buyer_Seller_Add_Data',Buyer_Seller_Add_Data.as_view()),
path('auth/Buyer_Seller_All_Data',Buyer_Seller_All_Data.as_view()),
path('auth/Delete_Timber_Data',Delete_Timber_Data.as_view()),
path('auth/Select_Data',Select_Data.as_view()),
path('auth/Firm_Registration',Firm_Registration.as_view()),
path('auth/Firm_Registration',Firm_Registration.as_view()),
path('auth/check_usr_category',check_usr_category.as_view()),
path('auth/View_Buyer_Requirement',View_Buyer_Requirement.as_view()),
path('auth/View_All_BuyerRequirement',View_All_BuyerRequirement.as_view()),
path('auth/Buyer_SelectedDta',Buyer_SelectedDta.as_view()),
path('auth/SellerView_SelectedDta',SellerView_SelectedDta.as_view()),
path('auth/requirement_division_filtration',requirement_division_filtration.as_view()),
path('auth/addtimber_division_filtration',addtimber_division_filtration.as_view()),
path('auth/requirement_district_species_filtration',requirement_district_species_filtration.as_view()),
path('auth/addtimber_district_species_filtration',addtimber_district_species_filtration.as_view()),
path('auth/LoadTreeSpecies',LoadTreeSpecies.as_view()),
path('auth/table_eleven',table_eleven.as_view()),


path('auth/scaned_details',scaned_details.as_view()),
path('auth/ScanedListApplication',ScanedListApplication.as_view()),
path('auth/Add_Timber_Details',Add_Timber_Details.as_view()),
path('auth/Add_Requirement',Add_Requirement.as_view()),

path('auth/table_one/', views.table_one.as_view(),name='tabel_one'),
path('auth/dfo_table_one/', views.dfo_table_one.as_view(),name='dfo_table_one'),
path('auth/sfd_table_one/', views.sfd_table_one.as_view(),name='sfd_table_one'),


path('auth/table_two/', views.table_two.as_view(),name='tabel_two'),
path('auth/dfo_table_two/', views.dfo_table_two.as_view(),name='dfo_table_two'),
path('auth/sfd_table_two/', views.sfd_table_two.as_view(),name='sfd_table_two'),



path('auth/table_three/', views.table_three.as_view(),name='tabel_three'),
path('auth/dfo_table_three/', views.dfo_table_three.as_view(),name='dfo_tabel_three'),
path('auth/sfd_table_three/', views.sfd_table_three.as_view(),name='sfd_tabel_three'),


path('auth/table_four/', views.table_four.as_view(),name='tabel_four'),
path('auth/dfo_table_four/', views.dfo_table_four.as_view(),name='dfo_tabel_four'),
path('auth/sfd_table_four/', views.sfd_table_four.as_view(),name='sfd_tabel_four'),

path('auth/table_five/', views.table_five.as_view(),name='table_five'),
path('auth/dfo_table_five/', views.dfo_table_five.as_view(),name='dfo_table_five'),
path('auth/sfd_table_five/', views.sfd_table_five.as_view(),name='sfd_table_five'),



path('auth/table_six/', views.table_six.as_view(),name='table_six'),
path('auth/dfo_table_six/', views.dfo_table_six.as_view(),name='dfo_table_six'),
path('auth/sfd_table_six/', views.sfd_table_six.as_view(),name='sfd_table_six'),




path('auth/table_seven/', views.table_seven.as_view(),name='table_seven'),
path('auth/dfo_table_seven/', views.dfo_table_seven.as_view(),name='dfo_table_seven'),
path('auth/sfd_table_seven/', views.sfd_table_seven.as_view(),name='sfd_table_seven'),

path('auth/table_eight/', views.table_eight.as_view(),name='table_eight'),
path('auth/dfo_table_eight/', views.dfo_table_eight.as_view(),name='dfo_table_eight'),
path('auth/sfd_table_eight/', views.sfd_table_eight.as_view(),name='sfd_table_eight'),


path('auth/table_nine/', views.table_nine.as_view(),name='table_nine'),
path('auth/dfo_table_nine/', views.dfo_table_nine.as_view(),name='dfo_table_nine'),
path('auth/sfd_table_nine/', views.sfd_table_nine.as_view(),name='sfd_table_nine'),


path('auth/table_noc_one/', views.table_noc_one.as_view(),name='table_noc_one'),
path('auth/dfo_table_noc_one/', views.dfo_table_noc_one.as_view(),name='dfo_table_noc_one'),
path('auth/sfd_table_noc_one/', views.sfd_table_noc_one.as_view(),name='sfd_table_noc_one'),





path('auth/Apply_for_noc/', views.Apply_for_noc.as_view(),name='Apply_for_noc'),
path('auth/NocListApplication/', views.NocListApplication.as_view(),name='NocListApplication'),
path('auth/NocViewApplication', views.NocViewApplication.as_view(),name='NocViewApplication'),


path('auth/new_noc_pdf/<int:applicant_no>/', new_noc_pdf,name='new_noc_pdf'),
path('auth/DeemedApprovedList', views.DeemedApprovedList.as_view(),name='DeemedApprovedList'),
path('auth/UserNocListApplication', views.UserNocListApplication.as_view(),name='UserNocListApplication'),
path('auth/UpdateLocationImage', views.UpdateLocationImage.as_view(),name='UpdateLocationImage'),

path('auth/GetLocationDataNew', views.GetLocationDataNew.as_view(),name='GetLocationDataNew'),
path('auth/register_otp_verification',register_otp_verification.as_view()),
path('auth/register_Otp_verify',register_Otp_verify.as_view()),
path('auth/set_newpassword',set_newpassword.as_view()),
path('auth/logout', LogoutView.as_view(), name='knox_logout'),

path('auth/villages/',views.get_villages.as_view(), name='get_village_details'),
path('auth/transit_details/',views.get_transit_details.as_view(), name='get_transit_details'),
path('auth/field_verify/',views.deputy_field_verify.as_view(),name="deputy_field_verify"),
path('auth/new_application_form/',views.new_application_form.as_view(),name="new_application_form"),
path('auth/get_app_details_new/',views.get_app_details_new.as_view(),name="get_app_details_new"),
path('auth/get_deputies/',views.get_deputies.as_view(),name="fet_deputies"),
path('auth/assgin_deputy/',views.assgin_deputy.as_view(),name="assgin_deputy"),
path('auth/CheckTransit/',views.CheckTransit.as_view(),name="CheckTransit"),
path('auth/apply_orign_transit/',views.apply_orign_transit.as_view(),name="apply_orign_transit"),
path('auth/SeeTransit/',views.SeeTransit.as_view(),name="SeeTransit"),
path('auth/approve_cutting_pass_new/',views.approve_cutting_pass_new.as_view(),name="approve_cutting_pass_new"),

path('auth/ApproveNewProductTransit/',views.ApproveNewProductTransit.as_view(),name="ApproveNewProductTransit"),
path('auth/get_req_log/',views.GetReq_log.as_view(),name="get_req_log"),
path('auth/get_verified_log/',views.GetVerified_log.as_view(),name="get_verified_log"),
path('auth/get_approved_log/',views.GetApproved_log.as_view(),name="get_approved_log"),
path('auth/GetPasses/',views.GetPasses.as_view(),name="GetPasses"),
path('auth/GetTransitPasses/',views.GetTransitPasses.as_view(),name="GetTransitPasses"),
path('auth/GetCuttingPasses/',views.GetCuttingPasses.as_view(),name="GetCuttingPasses"),
path('auth/GetOfficerTransitPasses/',views.GetOfficerTransitPasses.as_view(),name="GetOfficerTransitPasses"),
path('auth/AddLocation/',views.AddLocation.as_view(),name="AddLocation"),
path('auth/newsendotp/',views.newsendotp.as_view(),name="newsendotp"),



]