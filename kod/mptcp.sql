-- MySQL dump 10.16  Distrib 10.1.30-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: mptcp
-- ------------------------------------------------------
-- Server version	10.1.30-MariaDB-0ubuntu0.17.10.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `conn`
--

DROP TABLE IF EXISTS `conn`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `conn` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_src` varchar(30) DEFAULT NULL,
  `ip_dst` varchar(30) DEFAULT NULL,
  `keya` varchar(50) DEFAULT NULL,
  `keyb` varchar(50) DEFAULT NULL,
  `tokena` varchar(50) DEFAULT NULL,
  `tokenb` varchar(50) DEFAULT NULL,
  `tcp_src` int(11) DEFAULT NULL,
  `tcp_dst` int(11) DEFAULT NULL,
  `src` varchar(50) DEFAULT NULL,
  `dst` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tokenb` (`tokenb`),
  UNIQUE KEY `tokena` (`tokena`)
) ENGINE=InnoDB AUTO_INCREMENT=2705 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conn`
--

LOCK TABLES `conn` WRITE;
/*!40000 ALTER TABLE `conn` DISABLE KEYS */;
INSERT INTO `conn` VALUES (2701,'10.0.0.1','10.0.0.4','64f76d87f3755918','d0437295734868a3','2600304426','3227895299',59892,5001,'08:00:27:5f:ab:7f','08:00:27:77:27:8c'),(2702,'10.0.0.1','10.0.0.4','d338cce47faa62cf','a1bc8308cba55c3f','2791923709','2796413000',59894,5001,'08:00:27:5f:ab:7f','08:00:27:77:27:8c'),(2703,'10.0.0.1','10.0.0.4','a405a3e347eb03fb','4c3bce839f6802fb','21286615','529383234',59896,5001,'08:00:27:5f:ab:7f','08:00:27:77:27:8c'),(2704,'10.0.0.1','10.0.0.4','21d2f40b089f1621','9341049c627ea1b5','3951695333','331108702',59898,5001,'08:00:27:5f:ab:7f','08:00:27:77:27:8c');
/*!40000 ALTER TABLE `conn` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `conn_path`
--

DROP TABLE IF EXISTS `conn_path`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `conn_path` (
  `conn_id` int(11) NOT NULL,
  `path_id` int(11) NOT NULL,
  PRIMARY KEY (`conn_id`,`path_id`),
  KEY `conn_path_ibfk_2` (`path_id`),
  CONSTRAINT `conn_path_ibfk_1` FOREIGN KEY (`conn_id`) REFERENCES `conn` (`id`),
  CONSTRAINT `conn_path_ibfk_2` FOREIGN KEY (`path_id`) REFERENCES `path` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conn_path`
--

LOCK TABLES `conn_path` WRITE;
/*!40000 ALTER TABLE `conn_path` DISABLE KEYS */;
INSERT INTO `conn_path` VALUES (2701,176),(2701,177),(2703,178),(2703,179),(2703,180),(2703,181),(2704,182),(2704,183),(2704,184),(2704,185);
/*!40000 ALTER TABLE `conn_path` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `path`
--

DROP TABLE IF EXISTS `path`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `path` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nodes` varchar(100) DEFAULT NULL,
  `count` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=186 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `path`
--

LOCK TABLES `path` WRITE;
/*!40000 ALTER TABLE `path` DISABLE KEYS */;
INSERT INTO `path` VALUES (176,'08:00:27:5f:ab:7f 1 4 6 08:00:27:77:27:8c',2),(177,'08:00:27:5f:ab:7f 1 5 6 08:00:27:77:27:8c',1),(178,'08:00:27:5f:ab:7f 1 2 6 08:00:27:77:27:8c',1),(179,'08:00:27:5f:ab:7f 1 3 6 08:00:27:77:27:8c',1),(180,'08:00:27:5f:ab:7f 1 4 6 08:00:27:77:27:8c',1),(181,'08:00:27:5f:ab:7f 1 5 6 08:00:27:77:27:8c',1),(182,'08:00:27:5f:ab:7f 1 2 6 08:00:27:77:27:8c',1),(183,'08:00:27:5f:ab:7f 1 3 6 08:00:27:77:27:8c',1),(184,'08:00:27:5f:ab:7f 1 4 6 08:00:27:77:27:8c',1),(185,'08:00:27:5f:ab:7f 1 5 6 08:00:27:77:27:8c',1);
/*!40000 ALTER TABLE `path` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `subflow`
--

DROP TABLE IF EXISTS `subflow`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `subflow` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `connid` int(11) DEFAULT NULL,
  `tokenb` varchar(50) DEFAULT NULL,
  `noncea` varchar(50) DEFAULT NULL,
  `nonceb` varchar(50) DEFAULT NULL,
  `trunhash` varchar(100) DEFAULT NULL,
  `hash` varchar(100) DEFAULT NULL,
  `ip_src` varchar(30) DEFAULT NULL,
  `ip_dst` varchar(30) DEFAULT NULL,
  `tcp_src` int(11) DEFAULT NULL,
  `tcp_dst` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tcp_src` (`tcp_src`),
  KEY `connid` (`connid`),
  CONSTRAINT `subflow_ibfk_1` FOREIGN KEY (`connid`) REFERENCES `conn` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14907 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `subflow`
--

LOCK TABLES `subflow` WRITE;
/*!40000 ALTER TABLE `subflow` DISABLE KEYS */;
INSERT INTO `subflow` VALUES (14895,2701,'3227895299','d43d8616','330916af','7601959811503525176','de501a2954b6050e9c48876c34922f612cba0fb7','10.0.0.1','10.0.0.3',37911,5001),(14896,2701,'3227895299','6b3760c8','673b51e4','5226369410805341952','00c4f6b65662f71cf3a918aed7d052e423c00849','10.0.0.2','10.0.0.4',50021,5001),(14897,2701,'3227895299','f4b6bbbd','1ba36244','16825410458308027181','831c6de6eac28f35aa9f82998a61618b60e5f689','10.0.0.2','10.0.0.3',43169,5001),(14898,2702,'2796413000','981be356','9f80072e','9274314156476888340','85b58ae7e7a7b05160c5bad9e13bf0559b1050b3','10.0.0.1','10.0.0.3',41739,5001),(14899,2702,'2796413000','d2317217','d89697ab','1967070820244602010','f12a276deb9332b40860a2e68e9262b96b808254','10.0.0.2','10.0.0.4',56977,5001),(14900,2702,'2796413000','947a7185','8bd7a3c7','16329357378416868902','258e11b285c4fc3008b0696e6ac46c63c075eedc','10.0.0.2','10.0.0.3',39453,5001),(14901,2703,'529383234','1e3b4aeb','c1fddcd6','17291616065408958611','9bbec892a6d8697d43db23fb97ec0fb40a0c03c1','10.0.0.1','10.0.0.3',56753,5001),(14902,2703,'529383234','9fc2487d','f68d47c0','17775052199002463054','2e2c8bc7d7f1ac645d41f1195274ebb89bbb9c91','10.0.0.2','10.0.0.4',44473,5001),(14903,2703,'529383234','572bb32d','5e900db8','9479401349847305820','33117e5d10320e2bed34bb6920bace9f0f3d37a3','10.0.0.2','10.0.0.3',47909,5001),(14904,2704,'331108702','ab061156','5d555388','9429827528543284527','3aba559e34a63431c7a4e470213f543f99ae4c0e','10.0.0.2','10.0.0.4',49695,5001),(14905,2704,'331108702','32538e04','0fcdc23c','10210631144158794588','1e201d04b3f8439ce83c1cd259579d6c7892930b','10.0.0.1','10.0.0.3',48407,5001),(14906,2704,'331108702','2b49584d','b1de9ee1','10750287855895741979','bbb5e44683bfeb138f7c4a3c7eb60721c9c95997','10.0.0.2','10.0.0.3',36519,5001);
/*!40000 ALTER TABLE `subflow` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-03-31 16:34:02
