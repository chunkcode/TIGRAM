<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Access-Control-Allow-Headers,Content-Type,Access-Control-Allow-Methods,Authorization,X-Requested-With');

// if(isset($_POST['Layer']) && isset($_POST['latitude']) && isset($_POST['longitude']))
// {
 $host        = "host = localhost";
 $port        = "port = 5432";
 $dbname      = "dbname = WebGIS";
 $credentials = "user = postgres password=pass@123";

 pg_connect( "$host $port $dbname $credentials"  );
 
 $table = $_POST["layers"];
 $latitude = $_POST["latitude"];
 $longitude = $_POST["longitude"];
 $column = $_POST["column"];

//  echo $table;
//  echo $latitude;
//  echo $longitude;

  $sql = "SELECT CONCAT(states_uts,' : ',".$column.") as ".$column." FROM public.".$table." WHERE ST_Within(ST_GeomFromText('POINT(".$longitude." ".$latitude.")', 4326), ST_Buffer(geom, 0))"; 
// $sql = "SELECT i FROM public.belowpovertyline WHERE ST_Within(ST_GeomFromText('POINT(85.23462126709246 22.87238153587446)',4326), ST_Buffer(geom,0))";
   // $sql ="SELECT i FROM ".$table." WHERE ST_DWithin(geom, 'SRID=4326;POINT(  ".$longitude." ".$latitude.")')";
   // echo $sql; 
   $out=pg_query($sql);

if($out){
      if(pg_num_rows($out)>0){
         $rows=pg_fetch_assoc($out);
         echo $rows[$column].';'.$latitude.';'.$longitude;
      }
}

?>