from rest_framework import serializers
from my_app.models import CustomUser,Village,TempLinkage,Applicationform,Timberlogdetails,image_documents,ApprovedTimberLog,TransitPass,ProductTransit
from django.http import JsonResponse
from django.contrib.auth import authenticate



#user Serializer
class UserSerializer(serializers.ModelSerializer):
	class Meta:
		model = CustomUser
		fields = ('id','phone','name','email','address','photo_proof_name','photo_proof_no','photo_proof_img','usr_category')

#Register Serializer
class VillageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Village
        fields = ('id','village_name','is_notified')
        
class TempSerializer(serializers.ModelSerializer):
    class Meta:
        model = TempLinkage
        fields = ('range','division')
        
class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Applicationform
        fields = '__all__'
class TimberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timberlogdetails
        fields = '__all__'
class ImageSerial(serializers.ModelSerializer):
    class Meta:
        model = image_documents
        fields = '__all__'
        
class RegisterSerializer(serializers.ModelSerializer):
	class Meta:
		model = CustomUser
		fields = ('id','phone','name','email','password','address','photo_proof_name','photo_proof_no','photo_proof_img')
		extra_kwargs = {'password':{'write_only':True}}
		
	def create(self,validated_data):
		print(validated_data,"*(*(*(*(")
		customuser = CustomUser.objects.create_user(address = validated_data['address'],photo_proof_name = validated_data['photo_proof_name'],photo_proof_no = validated_data['photo_proof_no'],phone =validated_data['phone'],name=validated_data['name'],email=validated_data["email"],password=validated_data['password'])
		return customuser

#login Serializer
class LoginSerializer(serializers.Serializer):
	class Meta:
		model = CustomUser
		fields = ('id','phone','name','email','password')

	email = serializers.CharField()
	password = serializers.CharField()

	def validate(self,data):
		customuser = authenticate(**data)
		if customuser and customuser.is_active:
			return customuser
		raise serializers.ValidationError("Incorrect Credentials")


class AppSerial(serializers.ModelSerializer):
    class Meta:
        model = Applicationform
        fields = '__all__'

class ATimSerial(serializers.ModelSerializer):
    class Meta:
        model = ApprovedTimberLog
        fields = '__all__'

class Transits_serial(serializers.ModelSerializer):
    class Meta:
        model = TransitPass
        fields = '__all__'

class Produsct_ch_serial(serializers.ModelSerializer):
    class Meta:
        model = ProductTransit
        fields = '__all__'