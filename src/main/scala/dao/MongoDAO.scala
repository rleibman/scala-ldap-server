package dao

import scala.collection.JavaConverters._
import akka.actor.ActorSystem
import scala.concurrent.Future
import ldap.Config
import ldap.Node
import java.util.UUID
import org.apache.commons.codec.binary.Hex
import akka.event.Logging
import reactivemongo.bson._

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
  val nodeCollectionFut = dbFut.map(_("nodes"))

  implicit val reader = new BSONDocumentReader[Node] {
    override def read(bson: BSONDocument): Node = {
      val userAttributes = bson.getAs[BSONDocument]("userAttributes").fold(Map[String, Seq[String]]()) {
        doc ⇒
          (doc.elements.map { bsonElement ⇒
            val values = bsonElement.value.asInstanceOf[BSONArray].as[List[String]]
            (bsonElement.name -> values)
          }).toMap
      }
      val operationalAttributes = bson.getAs[BSONDocument]("operationalAttributes").fold(Map[String, Seq[String]]()) {
        doc ⇒
          (doc.elements.map { bsonElement ⇒
            val values = bsonElement.value.asInstanceOf[BSONArray].as[List[String]]
            (bsonElement.name -> values)
          }).toMap
      }

      Node(
        bson.getAs[String]("_id").get,
        bson.getAs[String]("dn").get,
        operationalAttributes,
        userAttributes,
        bson.getAs[String]("parentId"),
        bson.getAs[Seq[String]]("children").getOrElse(Seq[String]())
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
        "operationalAttributes" -> BSONDocument(node.operationalAttributes.map { tuple ⇒
          (tuple._1, BSONArray(tuple._2.map(BSONString(_)).toArray))
        }),
        "parentId" -> node.parentId,
        "children" -> BSONArray(node.children)
      )

    }
  }

  def getNode(dn: String): Future[Option[Node]] = {
    for {
      collection <- nodeCollectionFut
      results <- collection.find(BSONDocument("dn" -> dn)).one[Node]
    } yield (results)

  }

  def getChildren(node: Node): Future[List[Node]] = {
    val parentId = BSONObjectID(Hex.decodeHex(node.id.toArray))
    for {
      collection <- nodeCollectionFut
      cursor <- collection.find(BSONDocument("parentId" -> parentId)).cursor[Node]().collect[List](-1, Cursor.FailOnError[List[Node]]())
    } yield (cursor)
  }

  def update(node: Node): Future[Node] = {
    val nodeWithId = if (node.id.isEmpty) {
      node.copy(id = UUID.randomUUID().toString())
    } else {
      node
    }
    for {
      collection <- nodeCollectionFut
      result <- collection.update(BSONDocument("dn" -> node.dn), nodeWithId, upsert = true)
    } yield (nodeWithId)
  }

}
