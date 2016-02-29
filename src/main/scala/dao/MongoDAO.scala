package dao

import scala.collection.JavaConverters._
import akka.actor.ActorSystem
import scala.concurrent.Future
import ldap.Config
import ldap.Node
import java.util.UUID
import org.apache.commons.codec.binary.Hex
import akka.event.Logging

class MongoDAO(implicit actorSystem: ActorSystem) extends Config {
  import reactivemongo.api._
  import actorSystem.dispatcher
  import reactivemongo.bson._
  val log = Logging(actorSystem, getClass)

  // gets an instance of the driver
  // (creates an actor system)
  val driver = new MongoDriver
  val connection = driver.connection(config.getStringList("scala-ldap-server.mongo.hosts").asScala)
  // Gets a reference to the database "plugin"
  val db = connection(config.getString("scala-ldap-server.mongo.dbName"))
  val nodeCollection = db("nodes")

  implicit val reader = new BSONDocumentReader[Node] {
    override def read(bson: BSONDocument): Node = {
      val attributes = bson.getAs[BSONDocument]("attributes").fold(Map[String, Seq[String]]()) {
        doc ⇒
          (doc.elements.map { tuple ⇒
            val values = tuple._2.asInstanceOf[BSONArray].as[List[String]]
            (tuple._1 -> values)
          }).toMap
      }

      Node(bson.getAs[BSONObjectID]("_id").get.stringify,
        bson.getAs[String]("dn").get,
        attributes,
        bson.getAs[BSONObjectID]("parentId").map(_.stringify),
        bson.getAs[Seq[BSONObjectID]]("children").fold(Seq[String]())(_.map(_.stringify)))
    }
  }

  //  id: String, dn: String, attributes: Map[String, Seq[String]], children: Seq[String]
  implicit val writer = new BSONDocumentWriter[Node] {
    override def write(node: Node): BSONDocument = {
      BSONDocument(
        "_id" -> BSONObjectID(Hex.decodeHex(node.id.toArray)),
        "dn" -> node.dn,
        "attributes" -> BSONDocument(node.attributes.map { tuple ⇒
          (tuple._1, BSONArray(tuple._2.map(BSONString(_)).toArray))
        }),
        "parentId" -> node.parentId.map(parentId ⇒ BSONObjectID(Hex.decodeHex(parentId.toArray))),
        "children" -> BSONArray(node.children.map(childId ⇒ BSONObjectID(Hex.decodeHex(childId.toArray)))))
    }
  }

  def getNode(dn: String): Future[Option[Node]] = nodeCollection.find(BSONDocument("dn" -> dn)).one[Node]

  def getChildren(node: Node): Future[List[Node]] = {
    val parentId = BSONObjectID(Hex.decodeHex(node.id.toArray))
    log.debug(s"Finding all children of node with parentId = ${parentId.stringify}")
    val found = nodeCollection.find(BSONDocument("parentId" -> parentId))
    val cursor = found.cursor[Node]()
    val res = cursor.collect[List]()
    res.onFailure {
      case t: Throwable ⇒ t.printStackTrace()
    }
    res
  }

  def update(node: Node): Future[Node] = {
    val nodeWithId = if (node.id.isEmpty) {
      node.copy(id = BSONObjectID.generate.stringify)
    } else {
      node
    }
    println(nodeWithId)
    val fut = nodeCollection.update(BSONDocument("dn" -> node.dn), nodeWithId, upsert = true)
    fut.map(result ⇒ nodeWithId)
  }

}
