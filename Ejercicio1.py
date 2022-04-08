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
        orders_api_url = "https://api.mercadolibre.com/orders"
        shipments_api_url = "https://api.mercadolibre.com/shipments"
        shipments_costs_api_url = ""
        shipments_payments_api_url = ""
        carrier_api_url = ""
        history_api_url = ""

        log_f(True, f"Prod Token URL SET: {token_api_url}\nProd Orders URL SET: {orders_api_url}\nProd Shipment URL SET: {shipments_api_url}", log_file)

    else:
        #DEV URLs
        token_api_url = "https://run.mocky.io/v3/64cda8d9-e817-487e-8faa-38a36697d118" #Creada el 02/04/2022. Válida hasta el 02/05/2022. DELETE: https://designer.mocky.io/manage/delete/64cda8d9-e817-487e-8faa-38a36697d118/w5qOk47iXs11l46nAE7RJDhFyJzI6jbY5EEe
        #orders_api_url = "https://run.mocky.io/v3/c84cada5-2079-400d-ab08-fe20d4f77164" #Ord/Shp: 4234456969/41226912948 - Creada el 03/04/2022. Válida hasta el 03/05/2022. DELETE: https://designer.mocky.io/manage/delete/c84cada5-2079-400d-ab08-fe20d4f77164/ze6I6n5TMHBfovYeX9O6bR0mL6YDNw2vnQJo
        #shipments_api_url = "https://run.mocky.io/v3/c7f54d12-95f4-4929-bf81-d37951b5c3f1" #Ord/Shp: 4234456969/41226912948 - #Creada el 03/04/2022. Válida hasta el 03/05/2022. DELETE: https://designer.mocky.io/manage/delete/c7f54d12-95f4-4929-bf81-d37951b5c3f1/ZvEJo8DHTEakBOZonPjV0pcMaArtjBCBjPVl
        orders_api_url = "https://run.mocky.io/v3/f78a9ea8-0715-421c-8378-973a86f4c0ea" #Ord/Shp: 4575311098/40585105306 - Creada el 03/04/2022. Válida hasta el 03/05/2022. DELETE: https://designer.mocky.io/manage/delete/f78a9ea8-0715-421c-8378-973a86f4c0ea/fduu5bQ5C6q4l1Bd9kusOHIkUsJk1eHuJzYb
        #shipments_api_url = "https://run.mocky.io/v3/0295d1df-2f13-4f21-89be-593e493702ab" #Ord/Shp: 4575311098/40585105306 - Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/0295d1df-2f13-4f21-89be-593e493702ab/RQvnD5I4jbq7aqrO1tAw29BpeAxILcHX9zVd
        shipments_api_url = "https://run.mocky.io/v3/9c8f5787-534a-44e7-826c-5076c8ff6a1b" #Ord/Shp: 4575311098/40585105306 - Creada el 08/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/9c8f5787-534a-44e7-826c-5076c8ff6a1b/NtXSEUfqHLjYDWK6dDg3tqEmLU3RtH2f1sTd
        shipments_costs_api_url = "https://run.mocky.io/v3/f3929e20-32ec-4f02-a645-f11c203e4a47" #Creada el 05/04/2022. Válida hasta el 05/05/2022. DELETE: https://designer.mocky.io/manage/delete/f3929e20-32ec-4f02-a645-f11c203e4a47/q0wVpkZTnnppvfn1wyPMv0aMajPFFR9rzQqG
        shipments_payments_api_url = "https://run.mocky.io/v3/9a6a6c66-e408-4f0a-aeed-71d45e45a2ae" #Creada el 05/04/2022. Válida hasta el 05/05/2022. DELETE: https://designer.mocky.io/manage/delete/9a6a6c66-e408-4f0a-aeed-71d45e45a2ae/NrGSEq8UskJj5irl8CFeV8pFzpfmzymWPN69
        carrier_api_url = "https://run.mocky.io/v3/dd14deec-6868-4607-a83e-7a24b6bd0069" #Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/dd14deec-6868-4607-a83e-7a24b6bd0069/6w57fX6YIOiakvxx5A2akUrovAabUamwRPoL
        #history_api_url = "https://run.mocky.io/v3/a3989531-51db-4170-9e44-d4a7944e0b15" #Ord: 5314127391 - Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/a3989531-51db-4170-9e44-d4a7944e0b15/CYB2QhpHJzQnNmB5rmLeFRoWxYC4yby7ZyR2
        history_api_url = "https://run.mocky.io/v3/821315c1-99d9-422f-821d-57d4df1cc636" #Ord/Shp: 4575311098/40585105306 - Creada el 06/04/2022. Válida hasta el 06/05/2022. DELETE: https://designer.mocky.io/manage/delete/821315c1-99d9-422f-821d-57d4df1cc636/TcXDL779llS06oM9Q2Lx5rLaHV6KnK3Nf38n
        log_f(True, f"Dev Token URL SET: {token_api_url}\nDev Orders URL SET: {orders_api_url}\nDev Shipment URL SET: {shipments_api_url}\nDev Shipment Costs URL SET: {shipments_costs_api_url}\nDev Shipment Payment URL SET: {shipments_payments_api_url}\nDev Shipment Carrier URL SET: {carrier_api_url}\nDev Shipment History URL SET: {history_api_url}", log_file)

    #TOKEN URL_Payload
    payload_token_api_url = {"grant_type": "authorization_code", "client_id": "", "client_secret": "", "code": "", "redirect_uri": ""}
    payload_token_api_url["client_id"] = args.client_id
    payload_token_api_url["client_secret"] = args.client_secret
    payload_token_api_url["code"] = args.code
    payload_token_api_url["redirect_uri"] = args.redirect_uri

    return(token_api_url, payload_token_api_url, orders_api_url, shipments_api_url, shipments_costs_api_url, shipments_payments_api_url, carrier_api_url, history_api_url)


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


#Build Report Line
def build_report_line_f(order, orders_api_response_dic, shipment, shipment_api_response_dic, shipments_costs_api_response_dic, shipments_payments_api_response_dic, shipments_carrier_api_response_dic, carrier_status_code, shipments_history_api_response_dic, history_status_code):
    product_list = [] #Listado de productos de una orden

    currency = orders_api_response_dic["currency_id"] #Obtengo "currency_id" del diccionario de response
    total_ammount = orders_api_response_dic["total_amount"] #Obtengo monto total de la orden
    
    
    #Proceso tipo de logística
    if "logistic_type" in shipment_api_response_dic:
        logistics = shipment_api_response_dic["logistic_type"] #Obtengo el tipo de logística
    else:
        logistics = "No encontrada"
    

    order_items = orders_api_response_dic["order_items"] #Obtengo listado de "order_items" del diccionario de response
    #Recorro el listado de "order_items"
    for order_item in order_items:
        item = (order_item["item"]) #Obtengo el diccionario de "item"
        product = item["title"] #Obtengo el producto asociado al "item"        
        variations = item["variation_attributes"] #Obtengo el listado de variaciones del "item"
        
        #Recorro el listado de variaciones y obtengo el nombre y valor de la variación
        for variation in variations:
            variation_name = variation["name"]
            variation_val = variation["value_name"]
            variation_desc = f"- {variation_name} {variation_val}"
            product = f"{product}{variation_desc}"
        
        #Obtengo el precio del "item" y termino de armar la concatenación producto - variaciones - precio
        price = order_item["unit_price"]
        product = f"{product} - ${price}"
        product_list.append(product)

    product_string = " ".join(product_list) #Convierto el listado de productos en string separado por espacios  

    #Proceso origen del envío
    if logistics == "fulfillment":
        origin = "MELI"
    else:
        origin = "Vendedor"

    
    #Proceso destino del envío
    agency = shipment_api_response_dic["receiver_address"]["agency"] #Obtengo agencia de destino
    if agency:
        destination = "Agencia"
        agency_id = agency["agency_id"]
        carrier_id = agency["carrier_id"]
        street = "null"
        street_number = "null"
        neighborhood = "null"
        city = "null"
        municipality = "null"
        state = "null"
        country = "null"
        zip_code = "null"
    else:
        destination = "Domicilio"
        agency_id = "null"
        carrier_id = "null"
        street = shipment_api_response_dic["receiver_address"]["street_name"] #Calle
        street_number = shipment_api_response_dic["receiver_address"]["street_number"] #Altura
        neighborhood = shipment_api_response_dic["receiver_address"]["neighborhood"]["name"] #Barrio
        city = shipment_api_response_dic["receiver_address"]["city"]["name"] #Localidad
        municipality = shipment_api_response_dic["receiver_address"]["municipality"]["name"] #Departamento
        state = shipment_api_response_dic["receiver_address"]["state"]["name"] #Provincia
        country = shipment_api_response_dic["receiver_address"]["country"]["name"] #País
        zip_code = shipment_api_response_dic["receiver_address"]["zip_code"] #Código Postal


    #Proceso costos del envío
    buyer_cost_ammount = 0
    seller_cost_ammount = 0

    shipment_gross_amount = shipments_costs_api_response_dic["gross_amount"]
    buyer_cost_ammount = shipments_costs_api_response_dic["receiver"]["cost"]
    buyer_id = shipments_costs_api_response_dic["receiver"]["user_id"]
        
    senders = shipments_costs_api_response_dic["senders"]    
    for sender in senders:
        seller_cost_ammount += sender["cost"]


    #Proceso pagos del envío
    buyer_paid_ammount = 0
    seller_paid_ammount = 0

    payments = []
    payments = shipments_payments_api_response_dic
    for payment in payments:
        if payment["user_id"] == buyer_id:
            buyer_paid_ammount = payment["amount"]
        else:
            seller_paid_ammount += payment["amount"]


    #Busco carrier
    if carrier_status_code != 200:
        carrier = "No pudo obtenerse"
    else:
        carrier = shipments_carrier_api_response_dic["name"]


    #Proceso fechas de entrega
    estimated_delivery_time = "null"
    estimated_delivery_final = "null"
    delivery_date = "null"
    delivery_result = "null"

    if "estimated_delivery_time" in shipment_api_response_dic["shipping_option"]:
        estimated_delivery_time = shipment_api_response_dic["shipping_option"]["estimated_delivery_time"]["date"]
        
    
    if "estimated_delivery_final" in shipment_api_response_dic["shipping_option"]:
        estimated_delivery_final = shipment_api_response_dic["shipping_option"]["estimated_delivery_final"]["date"]
        

    if history_status_code != 200:
        delivery_date = "No pudo obtenerse"
    else:
        if shipments_history_api_response_dic["status"] == "delivered":
            delivery_date = shipments_history_api_response_dic["date_history"]["date_delivered"]
            if estimated_delivery_final:
                if datetime.strptime(delivery_date[0:10],"%Y-%m-%d") <= datetime.strptime(estimated_delivery_final[0:10],"%Y-%m-%d"):
                    delivery_result = "En tiempo y forma"
                else:
                    delivery_result = "Con retraso"
            else:
                if estimated_delivery_time:
                    if datetime.strptime(delivery_date[0:10],"%Y-%m-%d") <= datetime.strptime(estimated_delivery_time[0:10],"%Y-%m-%d"):
                        delivery_result = "En tiempo y forma"
                    else:
                        delivery_result = "Con retraso"
                else:
                    delivery_result = "No puede calcularse"
        else:            
            delivery_date = "No entregado aún"


    #Armo registro de archivo csv
    line = f"{order}|{product_string}|{currency}|{total_ammount}|{logistics}|{shipment}|{origin}|{destination}|{agency_id}|{carrier_id}|{street}|{street_number}|{neighborhood}|{city}|{municipality}|{state}|{country}|{zip_code}|${shipment_gross_amount}|${seller_cost_ammount}|${seller_paid_ammount}|${buyer_cost_ammount}|${buyer_paid_ammount}|{carrier}|{delivery_date}|{estimated_delivery_time}|{estimated_delivery_final}|{delivery_result}"

    return line


#Process Order List
def process_orders_f(orders_list, token, orders_api_url, shipments_api_url, shipments_costs_api_url, shipments_payments_api_url, carrier_api_url, history_api_url, date, log_file, is_prod):
        api_token = {"Authorization": f"Bearer {token}"}
        output_path = os.environ.get('PY_REPORT_PATH')

        try:
            #Open report file
            order_report_file = open_file_f(output_path, "py_order_report", date, "csv")
            order_report_file.write("NRO_ORDEN|PRODUCTO|MONEDA|SUBTOTAL|LOGISTICA|NRO_ENVIO|ORIGEN|DESTINO|ID_AGENCIA|ID_CARRIER|CALLE|ALTURA|BARRIO|LOCALIDAD|DEPARTAMENTO|PROVINCIA|PAIS|COD_POSTAL|COSTO_ENVIO|COSTO_VENDEDOR|PAGO_VENDEDOR|COSTO_COMPRADOR|PAGO_COMPAROR|PROVEEDOR|DIA_ENTREGA|PROMESA_ENTREGA|FECHA_FINAL|RESULTADO_ENTREGA\n")
            
            for order in orders_list:
                #Build URL by order num and invoke API
                orders_api_url_order = f"{orders_api_url}/{order}"
                log_f(True, f"Invoking ORDER API [GET] - URL: {orders_api_url_order}\nWith Order: {order}", log_file)
                orders_api_response = requests.get(orders_api_url_order, headers=api_token)
                log_f(False, f"Response Status Code: {orders_api_response.status_code}\nResponse: {orders_api_response.text}", log_file)

                #Process response
                if orders_api_response.status_code == 200:
                    log_f(True, f"Se procesa orden: {order}", log_file)

                    #Get shipping id
                    orders_api_response_dic = json.loads(orders_api_response.text)
                    shipment = orders_api_response_dic["shipping"]["id"]

                    #Build URL by shipping num and invoke API
                    shipments_api_url_shipment = f"{shipments_api_url}/{shipment}"
                    log_f(True, f"Invoking SHIPMENT API [GET] - URL: {shipments_api_url_shipment}\nWith Shipment: {shipment}", log_file)
                    shipments_api_response = requests.get(shipments_api_url_shipment, headers=api_token)
                    log_f(False, f"Response Status Code: {shipments_api_response.status_code}\nResponse: {shipments_api_response.text}", log_file)

                    if shipments_api_response.status_code == 200:

                        #Build URL by shipping and invoke costs API
                        if is_prod:
                            shipments_api_url_costs = f"{shipments_api_url}/{shipment}/costs"
                        else:
                            shipments_api_url_costs = shipments_costs_api_url
                        log_f(True, f"Invoking SHIPMENT COSTS API [GET] - URL: {shipments_api_url_costs}\nWith Shipment: {shipment}", log_file)
                        shipments_costs_api_response = requests.get(shipments_api_url_costs, headers=api_token)
                        log_f(False, f"Response Status Code: {shipments_costs_api_response.status_code}\nResponse: {shipments_costs_api_response.text}", log_file)

                        if shipments_costs_api_response.status_code == 200:

                            #Build URL by shipping and invoke payments API
                            if is_prod:
                                shipments_api_url_payments = f"{shipments_api_url}/{shipment}/payments"
                            else:
                                shipments_api_url_payments = shipments_payments_api_url
                            log_f(True, f"Invoking SHIPMENT PAYMENTS API [GET] - URL: {shipments_api_url_payments}\nWith Shipment: {shipment}", log_file)
                            shipments_payments_api_response = requests.get(shipments_api_url_payments, headers=api_token)
                            log_f(False, f"Response Status Code: {shipments_payments_api_response.status_code}\nResponse: {shipments_payments_api_response.text}", log_file)

                            if shipments_payments_api_response.status_code == 200:
                            
                                #Build URL by shipping and invoke carrier API
                                if is_prod:
                                    shipments_api_url_carrier = f"{shipments_api_url}/{shipment}/carrier"
                                else:
                                    shipments_api_url_carrier = carrier_api_url
                                log_f(True, f"Invoking SHIPMENT CARRIER API [GET] - URL: {shipments_api_url_carrier}\nWith Shipment: {shipment}", log_file)
                                shipments_carrier_api_response = requests.get(shipments_api_url_carrier, headers=api_token)
                                log_f(False, f"Response Status Code: {shipments_carrier_api_response.status_code}\nResponse: {shipments_carrier_api_response.text}", log_file)
                                

                                #Build URL by shipping and invoke history API
                                if is_prod:
                                    shipments_api_url_history = f"{shipments_api_url}/{shipment}/history"
                                else:
                                    shipments_api_url_history = history_api_url
                                log_f(True, f"Invoking SHIPMENT HISTORY API [GET] - URL: {shipments_api_url_history}\nWith Shipment: {shipment}", log_file)
                                shipments_history_api_response = requests.get(shipments_api_url_history, headers=api_token)
                                log_f(False, f"Response Status Code: {shipments_history_api_response.status_code}\nResponse: {shipments_history_api_response.text}", log_file)


                                #Build Order Report line
                                log_f(True, f"Starting record construction for Order: {order}, Shipment: {shipment}...", log_file)
                                report_line = build_report_line_f(order, orders_api_response_dic, shipment, json.loads(shipments_api_response.text), json.loads(shipments_costs_api_response.text), json.loads(shipments_payments_api_response.text), json.loads(shipments_carrier_api_response.text), shipments_carrier_api_response.status_code, json.loads(shipments_history_api_response.text), shipments_history_api_response.status_code)
                                log_f(True, "Writting record to file...", log_file)
                                order_report_file.write(f"{report_line}\n")

                            else:
                                log_f(True, f"Falla en la integración de SHIPMENT PAYMENTS API [GET]. El servidor respondió con Status Code: {shipments_payments_api_response.status_code}", log_file)

                        else:
                            log_f(True, f"Falla en la integración de SHIPMENT COSTS API [GET]. El servidor respondió con Status Code: {shipments_costs_api_response.status_code}", log_file)

                    else:
                        log_f(True, f"Falla en la integración de SHIPMENT API [GET]. El servidor respondió con Status Code: {shipments_api_response.status_code}", log_file)

                else:
                    log_f(True, f"Falla en la integración de ORDER API [GET]. El servidor respondió con Status Code: {orders_api_response.status_code}", log_file)

        except Exception as e:
            log_f(True, e, log_file)

        finally:
            #Close report file
            order_report_file.close()


#Read input file
def read_input_file_f(path, file_name, log_file):
    orders_list = []

    try:
        input_file = open(f"{path}\{file_name}", "r")
        orders_list = input_file.read().splitlines()
        return orders_list

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
        log_file = open_file_f(os.environ.get('PY_LOG_PATH'), "py_log", date, "log")    
        log_f(True, "Iniciando ejecución...", log_file)

        #Check Environment
        run_env = os.environ.get('PY_ENV')
        is_prod = env_is_prod_f(run_env,valid_env_list)
        log_f(True, f"Entorno: {run_env}", log_file)

        #Read input file
        log_f(True, "Accediendo al archivo de entrada de órdenes...", log_file)
        orders_list = read_input_file_f(os.environ.get('PY_INPUT_FILE_PATH'), os.environ.get('PY_INPUT_FILE_NAME'), log_file)
        if len(orders_list) == 0:
            raise NameError(f"No se encontraron órdenes para procesar en el archivo de entrada")
        log_f(True, f"Se procesarán las siguientes órdenes...\n{orders_list}", log_file)

        #Set Environment Config
        token_api_url, payload_token_api_url, orders_api_url, shipments_api_url, shipments_costs_api_url, shipments_payments_api_url, carrier_api_url, history_api_url = set_env_f(is_prod, args, log_file)

        #Invoke Get Token
        token = get_token_f(token_api_url, payload_token_api_url, log_file)
        
        #Process Order List
        process_orders_f(orders_list, token, orders_api_url, shipments_api_url, shipments_costs_api_url, shipments_payments_api_url, carrier_api_url, history_api_url, date, log_file, is_prod)

    except Exception as e:
        log_f(True, e, log_file)

    finally:
        log_f(True, "Finalizando ejecución...", log_file)
        log_file.close()

if __name__ == "__main__":
    main()