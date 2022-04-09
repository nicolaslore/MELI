import os
import argparse
import requests
import json
from datetime import datetime

#Set Environment Config
def set_env_f(is_prod, args, log_file):
    if is_prod:
        #PROD URLs
        token_api_url = "https://api.mercadolibre.com/oauth/token"
        shipments_api_url = "https://api.mercadolibre.com/shipments"
        history_api_url = ""

        log_f(True, f"Prod Token URL SET: {token_api_url}\nProd Shipment URL SET: {shipments_api_url}", log_file)

    else:
        #DEV URLs
        token_api_url = "https://run.mocky.io/v3/64cda8d9-e817-487e-8faa-38a36697d118" #Creada el 02/04/2022. Válida hasta el 02/05/2022. DELETE: https://designer.mocky.io/manage/delete/64cda8d9-e817-487e-8faa-38a36697d118/w5qOk47iXs11l46nAE7RJDhFyJzI6jbY5EEe
        #shipments_api_url = "https://run.mocky.io/v3/c7f54d12-95f4-4929-bf81-d37951b5c3f1" #Ord/Shp: 4234456969/41226912948 - #Creada el 03/04/2022. Válida hasta el 03/05/2022. DELETE: https://designer.mocky.io/manage/delete/c7f54d12-95f4-4929-bf81-d37951b5c3f1/ZvEJo8DHTEakBOZonPjV0pcMaArtjBCBjPVl
        #shipments_api_url = "https://run.mocky.io/v3/0295d1df-2f13-4f21-89be-593e493702ab" #Ord/Shp: 4575311098/40585105306 - Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/0295d1df-2f13-4f21-89be-593e493702ab/RQvnD5I4jbq7aqrO1tAw29BpeAxILcHX9zVd
        shipments_api_url = "https://run.mocky.io/v3/9c8f5787-534a-44e7-826c-5076c8ff6a1b" #Ord/Shp: 4575311098/40585105306 - Creada el 08/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/9c8f5787-534a-44e7-826c-5076c8ff6a1b/NtXSEUfqHLjYDWK6dDg3tqEmLU3RtH2f1sTd
        history_api_url = "https://run.mocky.io/v3/8b3e8071-5506-45f3-9d38-dc1df612229d" # Ord/Shp: 5314127391 (mod). DELETE: https://designer.mocky.io/manage/delete/8b3e8071-5506-45f3-9d38-dc1df612229d/yFhm4Gz5CWeYEY15DVkIq3q4NWBiq2Wkwas8
        #history_api_url = "https://run.mocky.io/v3/a3989531-51db-4170-9e44-d4a7944e0b15" #Ord: 5314127391 - Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/a3989531-51db-4170-9e44-d4a7944e0b15/CYB2QhpHJzQnNmB5rmLeFRoWxYC4yby7ZyR2
        #history_api_url = "https://run.mocky.io/v3/821315c1-99d9-422f-821d-57d4df1cc636" #Ord/Shp: 4575311098/40585105306 - Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/821315c1-99d9-422f-821d-57d4df1cc636/TcXDL779llS06oM9Q2Lx5rLaHV6KnK3Nf38n
        log_f(True, f"Dev Token URL SET: {token_api_url}\nDev Shipment URL SET: {shipments_api_url}\nDev Shipment History URL SET: {history_api_url}", log_file)

    #TOKEN URL_Payload
    payload_token_api_url = {"grant_type": "authorization_code", "client_id": "", "client_secret": "", "code": "", "redirect_uri": ""}
    payload_token_api_url["client_id"] = args.client_id
    payload_token_api_url["client_secret"] = args.client_secret
    payload_token_api_url["code"] = args.code
    payload_token_api_url["redirect_uri"] = args.redirect_uri

    return(token_api_url, payload_token_api_url, shipments_api_url, history_api_url)


#Check Environment
def env_is_prod_f(run_env,valid_env_list):
    if run_env in valid_env_list:
        if run_env == "PROD":
            return True
        else:
            return False
    else:
        raise NameError(f"Variable de entorno inválida. Se recibió: {run_env}. Opciones válidas: {valid_env_list}")


#Get token
def get_token_f(token_api_url, payload_token_api_url, log_file):
    params = {}
    params["grant_type"] = payload_token_api_url["grant_type"]
    params["client_id"] = payload_token_api_url["client_id"]
    params["client_secret"] = "********************"
    params["code"] = payload_token_api_url["code"]
    params["redirect_uri"] = payload_token_api_url["redirect_uri"]
    
    log_f(True, f"Invoking TOKEN API [POST] - URL: {token_api_url}\nWith Params: {params}", log_file)
    token_api_response = requests.post(token_api_url, data=payload_token_api_url)
    log_f(False, f"Response Status Code: {token_api_response.status_code}\nResponse: {token_api_response.text}", log_file)
        
    if token_api_response.status_code == 200:
        token_api_dic = json.loads(token_api_response.text)
        token = token_api_dic["access_token"]
        log_f(True, f"Token: {token}", log_file)
        return token
    else:
        log_f(True, f"Falla en la integración. El servidor respondió con Status Code: {token_api_response.status_code}\nResponse: {token_api_response.text}", log_file)
        raise NameError(f"Error al obtener TOKEN.")


#Calcular retraso de entrega en HH:mm:ss
def calculate_delay_f(estimated_delivery, delivery):
    #Ejemplo de formato: 2022-02-24T16:39:17.017-04:00
    estimated_delivery_date = estimated_delivery[0:10]
    estimated_delivery_time = estimated_delivery[11:19]
    estimated_delivery_time_ms = estimated_delivery[20:23]
    estimated_delivery_date_tz = estimated_delivery[23:29]
    estimated_delivery_datetime = datetime.fromisoformat(f"{estimated_delivery_date} {estimated_delivery_time}:{estimated_delivery_time_ms}{estimated_delivery_date_tz}")

    delivery_date = delivery[0:10]
    delivery_time = delivery[11:19]
    delivery_time_ms = delivery[20:23]
    delivery_date_tz = delivery[23:29]
    delivery_datetime = datetime.fromisoformat(f"{delivery_date} {delivery_time}:{delivery_time_ms}{delivery_date_tz}")

    delivery_delay = delivery_datetime - estimated_delivery_datetime

    total_seconds = delivery_delay.total_seconds()

    hours = int(total_seconds/3600)
    minutes = int((total_seconds - hours*3600)/60)
    seconds = int(total_seconds - hours*3600 - minutes*60)
    delay = f"{hours}:{minutes}:{seconds}"
    
    return delay


#Build Report Line
def build_report_line_f(shipment, shipment_api_response_dic, shipments_history_api_response_dic, history_status_code):
        
    
    #Proceso tipo de logística
    if "logistic_type" in shipment_api_response_dic:
        logistics = shipment_api_response_dic["logistic_type"] #Obtengo el tipo de logística
    else:
        logistics = "No encontrada"
    

    #Proceso origen del envío
    if logistics == "fulfillment":
        origin = "MELI"
    else:
        origin = "Vendedor"

 
    #Proceso fechas de entrega
    estimated_delivery_time = "null"
    estimated_delivery_final = "null"
    delivery_date = "null"
    delivery_delay = "null"
    delivery_result = "null"
    shipment_status = shipments_history_api_response_dic["status"]

    if "estimated_delivery_time" in shipment_api_response_dic["shipping_option"]:
        estimated_delivery_time = shipment_api_response_dic["shipping_option"]["estimated_delivery_time"]["date"]
        
    
    if "estimated_delivery_final" in shipment_api_response_dic["shipping_option"]:
        estimated_delivery_final = shipment_api_response_dic["shipping_option"]["estimated_delivery_final"]["date"]
    

    if history_status_code != 200:
        delivery_date = "No pudo obtenerse"
    else:
        if shipment_status == "delivered":
            delivery_date = shipments_history_api_response_dic["date_history"]["date_delivered"]
            if estimated_delivery_time:
                if datetime.strptime(delivery_date[0:10],"%Y-%m-%d") <= datetime.strptime(estimated_delivery_time[0:10],"%Y-%m-%d"):
                        delivery_result = "En tiempo y forma"
                else:
                    delivery_result = "Con retraso"
                    delivery_delay = calculate_delay_f(estimated_delivery_time, delivery_date)
        
            else:
                if estimated_delivery_final:
                    if datetime.strptime(delivery_date[0:10],"%Y-%m-%d") <= datetime.strptime(estimated_delivery_final[0:10],"%Y-%m-%d"):
                        delivery_result = "En tiempo y forma"
                    else:
                        delivery_result = "Con retraso"
                        delivery_delay = calculate_delay_f(estimated_delivery_final, delivery_date)
                    
                else:
                    delivery_result = "No puede calcularse"
        else:            
            delivery_date = "No entregado aún"


    #Armo registro de archivo csv
    line = f"{shipment}|{shipment_status}|{logistics}|{origin}|{delivery_date}|{estimated_delivery_time}|{estimated_delivery_final}|{delivery_result}|{delivery_delay}"

    return line


#Process Order List
def process_shipments_f(shipments_list, token, shipments_api_url, history_api_url, date, log_file, is_prod):
        api_token = {"Authorization": f"Bearer {token}"}
        output_path = os.environ.get('PY_REPORT_PATH')

        try:
            #Open report file
            shipment_report_file = open_file_f(output_path, "py2_shipment_report", date, "csv")
            shipment_report_file.write("NRO_ENVIO|ESTADO|LOGISTICA|ORIGEN|DIA_ENTREGA|PROMESA_ENTREGA|FECHA_FINAL|RESULTADO_ENTREGA|RETRASO\n")
            
            for shipment in shipments_list:

                #Build URL by shipping num and invoke API
                shipments_api_url_shipment = f"{shipments_api_url}/{shipment}"
                log_f(True, f"Invoking SHIPMENT API [GET] - URL: {shipments_api_url_shipment}\nWith Shipment: {shipment}", log_file)
                shipments_api_response = requests.get(shipments_api_url_shipment, headers=api_token)
                log_f(False, f"Response Status Code: {shipments_api_response.status_code}\nResponse: {shipments_api_response.text}", log_file)

                if shipments_api_response.status_code == 200:
                        
                    #Build URL by shipping and invoke history API
                    if is_prod:
                        shipments_api_url_history = f"{shipments_api_url}/{shipment}/history"
                    else:
                        shipments_api_url_history = history_api_url
                    log_f(True, f"Invoking SHIPMENT HISTORY API [GET] - URL: {shipments_api_url_history}\nWith Shipment: {shipment}", log_file)
                    shipments_history_api_response = requests.get(shipments_api_url_history, headers=api_token)
                    log_f(False, f"Response Status Code: {shipments_history_api_response.status_code}\nResponse: {shipments_history_api_response.text}", log_file)


                    #Build Shipment Report line
                    log_f(True, f"Starting record construction for Shipment: {shipment}...", log_file)
                    report_line = build_report_line_f(shipment, json.loads(shipments_api_response.text), json.loads(shipments_history_api_response.text), shipments_history_api_response.status_code)
                    log_f(True, "Writting record to file...", log_file)
                    shipment_report_file.write(f"{report_line}\n")

                else:
                    log_f(True, f"Falla en la integración de SHIPMENT API [GET]. El servidor respondió con Status Code: {shipments_api_response.status_code}", log_file)

        except Exception as e:
            log_f(True, e, log_file)

        finally:
            #Close report file
            shipment_report_file.close()


#Read input file
def read_input_file_f(path, file_name, log_file):
    shipments_list = []

    try:
        input_file = open(f"{path}\{file_name}", "r")
        shipments_list = input_file.read().splitlines()
        return shipments_list

    except Exception as e:
        log_f(True, e, log_file)

    finally:
        input_file.close()


#Log to terminal and file
def log_f(log_to_terminal, line, log_file):
    log_file.write(f"{datetime.today().strftime('%d-%m-%Y_%H:%M:%S')} - {line}\n")
    if log_to_terminal:
        print(line)


#Init Log File
def open_file_f(path, name, date, ext):
    file_name = f"{name}_{date}.{ext}"
    return open(f"{path}\{file_name}", "w")


def main():
    
    #Definición y validación de input args
    parser = argparse.ArgumentParser()
    parser.add_argument("client_id",type=str,help="Id del aplicativo")
    parser.add_argument("client_secret",type=str,help="Secret del aplicativo")
    parser.add_argument("redirect_uri",type=str,help="URL del aplicativo. Ejemplo: https://www.test.com.ar/")
    parser.add_argument("code",type=str,help="Código de seguridad del servidor --> Ejecutar en un navegador por ejemplo: https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=1111111111111111&redirect_uri=https://www.test.com.ar/ --> En la URL completar con un valor válido luego de client_id= y redirect_uri= --> Redireccionará la url a una similar a: https://www.test.com.ar/?code=TG-624f9bb66d485a001a3a0900-129862714 --> Copiar el código: TG-624f9bb66d485a001a3a0900-129862714")
    args=parser.parse_args()

    valid_env_list = ["DEV","PROD"] #Valid Environment List

      
    try:
        date = datetime.today().strftime('%Y%m%d_%H%M%S')

        #Init Log File
        log_file = open_file_f(os.environ.get('PY_LOG_PATH'), "py2_log", date, "log")    
        log_f(True, "Iniciando ejecución...", log_file)

        #Check Environment
        run_env = os.environ.get('PY_ENV')
        is_prod = env_is_prod_f(run_env,valid_env_list)
        log_f(True, f"Entorno: {run_env}", log_file)

        #Read input file
        log_f(True, "Accediendo al archivo de entrada de envíos...", log_file)
        shipments_list = read_input_file_f(os.environ.get('PY_INPUT_FILE_PATH'), os.environ.get('PY_INPUT_FILE_NAME_2'), log_file)
        if len(shipments_list) == 0:
            raise NameError(f"No se encontraron envíos para procesar en el archivo de entrada")
        log_f(True, f"Se procesarán los siguientes envíos...\n{shipments_list}", log_file)

        #Set Environment Config
        token_api_url, payload_token_api_url, shipments_api_url, history_api_url = set_env_f(is_prod, args, log_file)

        #Invoke Get Token
        token = get_token_f(token_api_url, payload_token_api_url, log_file)
        
        #Process Order List
        process_shipments_f(shipments_list, token, shipments_api_url, history_api_url, date, log_file, is_prod)

    except Exception as e:
        log_f(True, e, log_file)

    finally:
        log_f(True, "Finalizando ejecución...", log_file)
        log_file.close()

if __name__ == "__main__":
    main()