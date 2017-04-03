package dao

import java.util.UUID

import scala.collection.JavaConverters.asScalaBufferConverter
import scala.concurrent.Future

import akka.actor.ActorSystem
import akka.event.Logging
import ldap.Config
import ldap.Node
import reactivemongo.bson.BSONArray
import reactivemongo.bson.BSONDocument
import reactivemongo.bson.BSONDocumentReader
import reactivemongo.bson.BSONDocumentWriter
import reactivemongo.bson.BSONString
import reactivemongo.bson.BSONRegex

class MongoDAO(implicit actorSystem: ActorSystem) extends Config {
  import actorSystem.dispatcher
  import reactivemongo.api._
  val log = Logging(actorSystem, getClass)

  // gets an instance of the driver
  // (creates an actor system)
  val driver = new MongoDriver
  val connection = driver.connection(config.getStringList("scala-ldap-server.mongo.hosts").asScala)
  // Gets a reference to the database "plugin"
  val dbFut = connection.database(config.getString("scala-ldap-server.mongo.dbName"))
  val nodeCollectionFut = dbFut.map(db => db("nodes"))

  implicit val reader = new BSONDocumentReader[Node] {
    override def read(bson: BSONDocument): Node = {
      val userAttributes = bson.getAs[BSONDocument]("userAttributes").fold(Map[String, Seq[String]]()) {
        doc ⇒
          (doc.elements.map { bsonElement ⇒
            val values = bsonElement.value.asInstanceOf[BSONArray].as[List[String]]
            (bsonElement.name -> values)
          }).toMap
      }
      Node(
        id = bson.getAs[String]("_id").get,
        dn = bson.getAs[String]("dn").get,
        userAttributes = userAttributes,
        parentId = bson.getAs[String]("parentId"),
        //Operational Attributes, per rfc4512
        creatorsName = bson.getAs[String]("creatorsName").get,
        createTimeStamp = bson.getAs[String]("createTimeStamp").get,
        modifiersName = bson.getAs[String]("modifiersName").get,
        modifyTimestamp = bson.getAs[String]("modifyTimestamp").get,
        structuralObjectClass = bson.getAs[String]("structuralObjectClass").get,
        governingStructureRule = bson.getAs[String]("governingStructureRule").get,
        objectClass = bson.getAs[List[String]]("objectClass").getOrElse(List.empty),
        attributeTypes = bson.getAs[List[String]]("attributeTypes").getOrElse(List.empty),
        matchingRules = bson.getAs[List[String]]("matchingRules").getOrElse(List.empty),
        distinguishedNameMatch = bson.getAs[List[String]]("distinguishedNameMatch").getOrElse(List.empty),
        ldapSyntaxes = bson.getAs[List[String]]("ldapSyntaxes").getOrElse(List.empty),
        matchingRuleUse = bson.getAs[List[String]]("matchingRuleUse").getOrElse(List.empty),
        subschemaSubentry = bson.getAs[String]("subschemaSubentry").get
      )
    }
  }

  //  id: String, dn: String, userAttributes: Map[String, Seq[String]], children: Seq[String]
  implicit val writer = new BSONDocumentWriter[Node] {
    override def write(node: Node): BSONDocument = {
      BSONDocument(
        "_id" -> node.id,
        "dn" -> node.dn,
        "userAttributes" -> BSONDocument(node.userAttributes.map { tuple ⇒
          (tuple._1, BSONArray(tuple._2.map(BSONString(_)).toArray))
        }),
        "parentId" -> node.parentId,
        //Operational Attributes, per rfc4512
        "creatorsName" -> node.creatorsName,
        "createTimeStamp" -> node.createTimeStamp,
        "modifiersName" -> node.modifiersName,
        "modifyTimestamp" -> node.modifyTimestamp,
        "structuralObjectClass" -> node.structuralObjectClass,
        "subschemaSubentry" -> node.subschemaSubentry,
        "governingStructureRule" -> node.governingStructureRule,
        "objectClass" -> node.objectClass,
        "attributeTypes" -> node.attributeTypes,
        "matchingRules" -> node.matchingRules,
        "distinguishedNameMatch" -> node.distinguishedNameMatch,
        "ldapSyntaxes" -> node.ldapSyntaxes,
        "matchingRuleUse" -> node.matchingRuleUse
      )

    }
  }

  def getNode(dn: String): Future[Option[Node]] = {
    val query = BSONDocument("dn" -> BSONRegex(dn, "i"))
    for {
      collection <- nodeCollectionFut
      results <- collection.find(query).one[Node]
    } yield (results)

  }

  def getChildren(node: Node): Future[List[Node]] = {
    val query = BSONDocument("parentId" -> node.id)
    for {
      collection <- nodeCollectionFut
      results <- collection.find(query).cursor[Node]().collect[List](-1, Cursor.FailOnError[List[Node]]())
    } yield (results)
  }

  def update(node: Node): Future[Node] = {
    val nodeWithId = if (node.id.isEmpty) {
      val id = UUID.randomUUID().toString()
      node.copy(id = id)
    } else {
      node
    }
    for {
      collection <- nodeCollectionFut
      result <- collection.update(BSONDocument("dn" -> node.dn), nodeWithId, upsert = true)
    } yield (nodeWithId)
  }

}
