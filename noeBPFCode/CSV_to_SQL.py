import pymysql
import csv

# Conexión a la base de datos MySQL
connection = pymysql.connect(
    host='localhost',
    user='victor',
    password='1234',
    database='test2'
)

cursor = connection.cursor()

try:
    # Leer el archivo CSV e insertar datos
    with open('captured_packets.csv', 'r') as file:
        csv_reader = csv.reader(file)
        headers = next(csv_reader)  # Leer el encabezado y omitirlo
        print(headers)
        expected_columns = 9  # Número de columnas esperadas en la tabla

        for row in csv_reader:
            # Verificar que la fila tiene el número correcto de columnas
            if len(row) != expected_columns:
                print(f"Fila inválida (esperadas {expected_columns} columnas, encontradas {len(row)}): {row}")
                continue  # Saltar filas mal formateadas

            # Ejecutar la consulta para insertar los datos
            cursor.execute(
                """
                INSERT INTO ebpf (Protocol, Timestamp, Source_IP, Source_Port, Destination_IP, Destination_Port, Packet_Length, Score_1, Score_2) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row[0],  # Protocol
                    row[1],  # Timestamp
                    row[2],  # Source IP
                    int(row[3]),  # Source Port
                    row[4],  # Destination IP
                    int(row[5]),  # Destination Port
                    int(row[6]),  # Packet Length
                    float(row[7]),  # Score 1
                    float(row[8])  # Score 2
                )
            )

    # Confirmar los cambios en la base de datos
    connection.commit()

except Exception as e:
    print(f"Error: {e}")
    connection.rollback()

finally:
    # Cerrar el cursor y la conexión
    cursor.close()
    connection.close()