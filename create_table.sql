DROP TABLE IF EXISTS `cache_base64data`;
CREATE TABLE `cache_base64data` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `timestamp` datetime NOT NULL,
  `session` char(32) NOT NULL,
  `base64_data` longtext,
  PRIMARY KEY (`id`),
  KEY `session` (`session`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
