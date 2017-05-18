package dao

import scala.concurrent.Future
import ldap._

trait DAO {
  def getNode(dn: String): Future[Option[Node]]
  def getChildren(node: Node): Future[List[Node]]
  def getSubtree(node: Node): Future[List[Node]]
  def update(node: Node): Future[Node]
}