CREATE USER 'victor'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON * . * TO 'victor'@'%';

create database ebpf;

CREATE TABLE ebpf (
    Protocol VARCHAR(10),
    Timestamp DATETIME,
    Source_IP VARCHAR(45),
    Source_Port INT,
    Destination_IP VARCHAR(45),
    Destination_Port INT,
    Packet_Length INT,
    Score_1 FLOAT,
    Score_2 FLOAT
);
